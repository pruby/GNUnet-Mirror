/**
 * @file xmlnode.c XML DOM functions
 *
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* A lot of this code at least resembles the code in libxode, but since
 * libxode uses memory pools that we simply have no need for, I decided to
 * write my own stuff.  Also, re-writing this lets me be as lightweight
 * as I want to be.  Thank you libxode for giving me a good starting point */

#include "platform.h"

#include "xmlnode.h"
#include "util.h"
#include "gnunet_util.h"

#ifdef _WIN32
# define NEWLINE_S "\r\n"
#else
# define NEWLINE_S "\n"
#endif

#define TRUE YES
#define FALSE NO

#define g_strdup STRDUP
#define g_malloc MALLOC
#define g_free FREE
#define g_return_if_fail(a) if(!(a)) return;
#define g_return_val_if_fail(a, val) if(!(a)) return (val);
#define gsize size_t
#define gboolean int
#define GString char 
#define g_string_new(a) STRDUP(a)

static void * g_memdup(const void * data,
		       size_t s) {
  void * ret;

  ret = MALLOC(s);
  memcpy(ret, data, s);
  return ret;
}

static char * g_string_append_len(char * prefix,
				  const void * data,
				  size_t s) {
  char * ret;

  ret = g_strdup_printf("%s%.*s",
			prefix,
			s,
			data);
  FREE(prefix);
  return ret;
}

static xmlnode*
new_node(const char *name, XMLNodeType type) {
  xmlnode *node = MALLOC(sizeof(xmlnode));
  
  node->name = g_strdup(name);
  node->type = type;
  return node;
}

xmlnode*
xmlnode_new(const char *name)
{
	g_return_val_if_fail(name != NULL, NULL);

	return new_node(name, XMLNODE_TYPE_TAG);
}

xmlnode *
xmlnode_new_child(xmlnode *parent, const char *name)
{
	xmlnode *node;

	g_return_val_if_fail(parent != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	node = new_node(name, XMLNODE_TYPE_TAG);

	xmlnode_insert_child(parent, node);

	return node;
}

void
xmlnode_insert_child(xmlnode *parent, xmlnode *child)
{
	g_return_if_fail(parent != NULL);
	g_return_if_fail(child != NULL);

	child->parent = parent;

	if(parent->lastchild) {
		parent->lastchild->next = child;
	} else {
		parent->child = child;
	}

	parent->lastchild = child;
}

void
xmlnode_insert_data(xmlnode *node, const char *data, int size)
{
	xmlnode *child;
	gsize real_size;

	g_return_if_fail(node != NULL);
	g_return_if_fail(data != NULL);
	g_return_if_fail(size != 0);

	real_size = size == -1 ? strlen(data) : size;

	child = new_node(NULL, XMLNODE_TYPE_DATA);

	child->data = g_memdup(data, real_size);
	child->data_sz = real_size;

	xmlnode_insert_child(node, child);
}

static void
xmlnode_remove_attrib(xmlnode *node, const char *attr)
{
	xmlnode *attr_node, *sibling = NULL;

	g_return_if_fail(node != NULL);
	g_return_if_fail(attr != NULL);

	for(attr_node = node->child; attr_node; attr_node = attr_node->next)
	{
		if(attr_node->type == XMLNODE_TYPE_ATTRIB &&
				!strcmp(attr_node->name, attr))
		{
			if(node->child == attr_node) {
				node->child = attr_node->next;
			} else {
				sibling->next = attr_node->next;
			}
			if (node->lastchild == attr_node) {
				node->lastchild = sibling;
			}
			xmlnode_free(attr_node);
			return;
		}
		sibling = attr_node;
	}
}



void
xmlnode_set_attrib(xmlnode *node, const char *attr, const char *value)
{
	xmlnode *attrib_node;

	g_return_if_fail(node != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(value != NULL);

	xmlnode_remove_attrib(node, attr);

	attrib_node = new_node(attr, XMLNODE_TYPE_ATTRIB);

	attrib_node->data = g_strdup(value);

	xmlnode_insert_child(node, attrib_node);
}

static void xmlnode_set_namespace(xmlnode *node, const char *xmlns)
{
	g_return_if_fail(node != NULL);

	g_free(node->xmlns);
	node->xmlns = g_strdup(xmlns);
}

static const char *xmlnode_get_namespace(xmlnode *node)
{
	g_return_val_if_fail(node != NULL, NULL);

	return node->xmlns;
}

void
xmlnode_free(xmlnode *node)
{
	xmlnode *x, *y;

	g_return_if_fail(node != NULL);

	x = node->child;
	while(x) {
		y = x->next;
		xmlnode_free(x);
		x = y;
	}

	g_free(node->name);
	g_free(node->data);
	g_free(node->xmlns);
	g_free(node);
}

xmlnode*
xmlnode_get_child(const xmlnode *parent, const char *name)
{
	return xmlnode_get_child_with_namespace(parent, name, NULL);
}

xmlnode *
xmlnode_get_child_with_namespace(const xmlnode *parent, const char *name, const char *ns)
{
	xmlnode *x, *ret = NULL;
	char *parent_name, *child_name;

	if (parent == NULL)
	  return NULL;
	if (name == NULL)
	  return NULL;

	parent_name = STRDUP(name);
	child_name = strstr(parent_name, "/");
	if (child_name != NULL) {
	  child_name[0] = '\0';
	  child_name++;
	}	  

	for(x = parent->child; x; x = x->next) {
		const char *xmlns = NULL;
		if(ns)
			xmlns = xmlnode_get_namespace(x);

		if(x->type == XMLNODE_TYPE_TAG && name && !strcmp(parent_name, x->name)
				&& (!ns || (xmlns && !strcmp(ns, xmlns)))) {
			ret = x;
			break;
		}
	}

	if (child_name && ret)
		ret = xmlnode_get_child(ret, child_name);

	FREE(parent_name);
	return ret;
}

char *
xmlnode_get_data(xmlnode *node)
{
	GString *str = NULL;
	xmlnode *c;
	
	if (node == NULL)
	  return NULL;

	for(c = node->child; c; c = c->next) {
		if(c->type == XMLNODE_TYPE_DATA) {
			if(!str)
				str = g_string_new("");
			str = g_string_append_len(str, c->data, c->data_sz);
		}
	}

	if (str == NULL)
		return NULL;

	return str;
}

struct _xmlnode_parser_data {
       xmlnode *current;
};

static void
xmlnode_parser_element_start_libxml(void *user_data,
				   const xmlChar *element_name, const xmlChar *prefix, const xmlChar *xmlns,
				   int nb_namespaces, const xmlChar **namespaces,
				   int nb_attributes, int nb_defaulted, const xmlChar **attributes)
{
	struct _xmlnode_parser_data *xpd = user_data;
	xmlnode *node;
	int i;

	if(!element_name) {
		return;
	} else {
	  if(xpd->current)
			node = xmlnode_new_child(xpd->current, (const char*) element_name);
		else
			node = xmlnode_new((const char *) element_name);

		xmlnode_set_namespace(node, (const char *) xmlns);

		for(i=0; i < nb_attributes * 5; i+=5) {
			char *txt;
			int attrib_len = attributes[i+4] - attributes[i+3];
			char *attrib = g_malloc(attrib_len + 1);
			memcpy(attrib, attributes[i+3], attrib_len);
			attrib[attrib_len] = '\0';
			txt = attrib;
			attrib = gaim_unescape_html(txt);
			g_free(txt);
			xmlnode_set_attrib(node, (const char*) attributes[i], attrib);
			g_free(attrib);
		}

		xpd->current = node;
	}
}

static void
xmlnode_parser_element_end_libxml(void *user_data, const xmlChar *element_name,
				 const xmlChar *prefix, const xmlChar *xmlns)
{
	struct _xmlnode_parser_data *xpd = user_data;

	if(!element_name || !xpd->current)
		return;

	if(xpd->current->parent) {
		if(!xmlStrcmp((xmlChar*) xpd->current->name, element_name))
			xpd->current = xpd->current->parent;
	}
}

static void
xmlnode_parser_element_text_libxml(void *user_data, const xmlChar *text, int text_len)
{
	struct _xmlnode_parser_data *xpd = user_data;

	if(!xpd->current)
		return;

	if(!text || !text_len)
		return;

	xmlnode_insert_data(xpd->current, (const char*) text, text_len);
}

static xmlSAXHandler xmlnode_parser_libxml = {
	.internalSubset         = NULL,
	.isStandalone           = NULL,
	.hasInternalSubset      = NULL,
	.hasExternalSubset      = NULL,
	.resolveEntity          = NULL,
	.getEntity              = NULL,
	.entityDecl             = NULL,
	.notationDecl           = NULL,
	.attributeDecl          = NULL,
	.elementDecl            = NULL,
	.unparsedEntityDecl     = NULL,
	.setDocumentLocator     = NULL,
	.startDocument          = NULL,
	.endDocument            = NULL,
	.startElement           = NULL,
	.endElement             = NULL,
	.reference              = NULL,
	.characters             = xmlnode_parser_element_text_libxml,
	.ignorableWhitespace    = NULL,
	.processingInstruction  = NULL,
	.comment                = NULL,
	.warning                = NULL,
	.error                  = NULL,
	.fatalError             = NULL,
	.getParameterEntity     = NULL,
	.cdataBlock             = NULL,
	.externalSubset         = NULL,
	.initialized            = XML_SAX2_MAGIC,
	._private               = NULL,
	.startElementNs         = xmlnode_parser_element_start_libxml,
	.endElementNs           = xmlnode_parser_element_end_libxml,
	.serror                 = NULL
};

xmlnode *
xmlnode_from_str(const char *str, int size)
{
	struct _xmlnode_parser_data *xpd;
	xmlnode *ret;
	gsize real_size;

	g_return_val_if_fail(str != NULL, NULL);

	real_size = size < 0 ? strlen(str) : size;
	xpd = MALLOC(sizeof(struct _xmlnode_parser_data));

	if (xmlSAXUserParseMemory(&xmlnode_parser_libxml, xpd, str, real_size) < 0) {
		while(xpd->current && xpd->current->parent)
			xpd->current = xpd->current->parent;
		if(xpd->current)
			xmlnode_free(xpd->current);
		xpd->current = NULL;
	}
	ret = xpd->current;
	g_free(xpd);
	return ret;
}

xmlnode *
xmlnode_get_next_twin(xmlnode *node)
{
	xmlnode *sibling;
	const char *ns = xmlnode_get_namespace(node);

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(node->type == XMLNODE_TYPE_TAG, NULL);

	for(sibling = node->next; sibling; sibling = sibling->next) {
		const char *xmlns = NULL;
		if(ns)
			xmlns = xmlnode_get_namespace(sibling);

		if(sibling->type == XMLNODE_TYPE_TAG && !strcmp(node->name, sibling->name) &&
				(!ns || (xmlns && !strcmp(ns, xmlns))))
			return sibling;
	}

	return NULL;
}
