/*
     This file is part of GNUnet

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.

     Portions of this code were adopted from the
     gnome-system-monitor v2.0.5, (C) 2001 Kevin Vandersloot


     Todo:
     - add any more StatEntries, update menu accordingly.
*/

#include "gnunet_afs_esed2.h"
#include "statistics.h"
#include "helper.h"
#include "main.h"
#include <glib.h>

#define UPDATE_INTERVAL (30 * cronSECONDS)

typedef struct {
  char * statName;
  long long value;
  long long lvalue;
  cron_t delta;
} StatPair;

static StatPair * lastStatValues;
static unsigned int lsv_size;
static cron_t lastUpdate;
static Mutex lock;

static void updateStatValues(GNUNET_TCP_SOCKET * sock) {
  STATS_CS_MESSAGE * statMsg;
  CS_HEADER csHdr;
  unsigned int count;
  unsigned int i;
  int j;
  int mpos;
  int found;
  char * optName;
  cron_t now;
  cron_t prev;
    
  cronTime(&now);
  MUTEX_LOCK(&lock);
  if (now - lastUpdate < UPDATE_INTERVAL) { 
    MUTEX_UNLOCK(&lock);
    return;
  }
  prev = lastUpdate;
  lastUpdate = now;
  csHdr.size 
    = htons(sizeof(CS_HEADER));
  csHdr.type
    = htons(STATS_CS_PROTO_GET_STATISTICS);
  if (SYSERR == writeToSocket(sock,
			      &csHdr)) {
    MUTEX_UNLOCK(&lock);
    return;
  }
  statMsg 
    = MALLOC(MAX_BUFFER_SIZE);
  statMsg->totalCounters 
    = htonl(1); /* to ensure we enter the loop */
  count = 0;
  while ( count < ntohl(statMsg->totalCounters) ) {
    if (SYSERR == readFromSocket(sock,
				 (CS_HEADER**)&statMsg)) {
      FREE(statMsg);
      MUTEX_UNLOCK(&lock);
      return;    
    }
    if (ntohs(statMsg->header.size) < sizeof(STATS_CS_MESSAGE)) {
      BREAK();
      break;
    }
    mpos = sizeof(unsigned long long) * ntohl(statMsg->statCounters);
    if ( ((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))
	 [ntohs(statMsg->header.size) - sizeof(STATS_CS_MESSAGE) - 1] != '\0') {
      BREAK();
      break;
    }      
    for (i=0;i<ntohl(statMsg->statCounters);i++) {
      optName = &((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos];
      if ( (mpos > ntohs(statMsg->header.size) - sizeof(STATS_CS_MESSAGE)) ||
	   (mpos + strlen(optName) + 1 > 
	    ntohs(statMsg->header.size) - sizeof(STATS_CS_MESSAGE)) ) {
	BREAK();
	break; /* out of bounds! */      
      }
      found = -1;
      for (j=0;j<lsv_size;j++) 
	if (0 == strcmp(optName,
			lastStatValues[j].statName))
	  found = j;
      if (found == -1) {
	found = lsv_size;
	GROW(lastStatValues,
	     lsv_size,
	     lsv_size+1);
	lastStatValues[found].statName
	  = STRDUP(optName);
      }
      lastStatValues[found].lvalue
	= lastStatValues[found].value;
      lastStatValues[found].value
	= ntohll(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values[i]);      
      lastStatValues[found].delta
	= now-prev;
      mpos += strlen(optName)+1;
    }    
    count += ntohl(statMsg->statCounters);
  } /* end while */
  FREE(statMsg);
  MUTEX_UNLOCK(&lock);
}

static int getStatValue(long long * value,
			long long * lvalue,
			cron_t * dtime,
			GNUNET_TCP_SOCKET * sock,
			const char * optName) {
  unsigned int i;

  *value = 0;
  if (lvalue != NULL)
    *lvalue = 0;
  updateStatValues(sock);
  MUTEX_LOCK(&lock);
  for (i=0;i<lsv_size;i++) {
    if (0 == strcmp(optName,
		    lastStatValues[i].statName)) {
      *value = lastStatValues[i].value;
      if (lvalue != NULL)
	*lvalue = lastStatValues[i].lvalue;
      if (dtime != NULL)
	*dtime = lastStatValues[i].delta;
      MUTEX_UNLOCK(&lock);
      return OK;
    }      
  }
  MUTEX_UNLOCK(&lock);
  return SYSERR;
}

/**
 * Callback function to obtain the latest stats
 * data for this stat display.
 */
typedef int (*UpdateData)(GNUNET_TCP_SOCKET * sock,
			  const void * closure,
			  gfloat ** data);

static int getConnectedNodesStat(GNUNET_TCP_SOCKET * sock,
				 const void * closure,
				 gfloat ** data) {
  long long val;
  char * cmh;
  long cval;

  cmh = getConfigurationOptionValue(sock,
				    "gnunetd",
				    "connection-max-hosts");
  if (cmh == NULL)
    return SYSERR;
  cval = atol(cmh);
  FREE(cmh);
  if (OK != getStatValue(&val,
			 NULL,
			 NULL,
			 sock,
			 _("# currently connected nodes"))) 
    return SYSERR;
  data[0][0] = 0.8 * val / cval;
  return OK;
}

static int getCPULoadStat(GNUNET_TCP_SOCKET * sock,
			  const void * closure,
			  gfloat ** data) {
  long long val;

  if (OK != getStatValue(&val,
			 NULL,
			 NULL,
			 sock,
			 _("% of allowed cpu load")))
    return SYSERR;
  data[0][0] = val / 125.0;
  return OK;
}

static const unsigned short afs_protocol_messages_queries[] = {
  AFS_p2p_PROTO_QUERY,
  AFS_p2p_PROTO_NSQUERY,
  0,
};

static const unsigned short afs_protocol_messages_content[] = {
  AFS_p2p_PROTO_3HASH_RESULT,
  AFS_p2p_PROTO_CHK_RESULT,
  AFS_p2p_PROTO_SBLOCK_RESULT,
  0,
};

static int getTrafficRecvStats(GNUNET_TCP_SOCKET * sock,
			       const void * closure,
			       gfloat ** data) {
  long long total;
  long long noise;
  long long content;
  long long queries;
  long long ltotal;
  long long lnoise;
  long long lcontent;
  long long lqueries;
  long long band;
  long long tmp;
  long long ltmp;
  cron_t dtime;
  char * available;
  char * buffer;
  int i;

  MUTEX_LOCK(&lock);
  if (OK != getStatValue(&total,	
			 &ltotal,
			 &dtime,
			 sock,
			 _("# bytes decrypted")))
    return SYSERR;
  if (OK != getStatValue(&noise,
			 &lnoise,
			 NULL,
			 sock,
			 _("# bytes of noise received")))
    return SYSERR;
  i = 0;
  content = lcontent = 0;
  buffer = MALLOC(512);
  while (afs_protocol_messages_content[i] != 0) {
    SNPRINTF(buffer, 
	     512,
	     _("# bytes received of type %d"),
	     afs_protocol_messages_content[i++]);
    if (OK == getStatValue(&tmp,
			   &ltmp,
			   NULL,
			   sock,
			   buffer)) {
      content += tmp;
      lcontent += ltmp;
    }
  }
  i = 0;
  while (afs_protocol_messages_queries[i] != 0) {
    SNPRINTF(buffer, 
	     512,
	     _("# bytes received of type %d"),
	     afs_protocol_messages_queries[i++]);
    if (OK == getStatValue(&tmp,
			   &ltmp,
			   NULL,
			   sock,
			   buffer)) {
      queries += tmp;
      lqueries += ltmp;
    }
  }
  FREE(buffer);
  MUTEX_UNLOCK(&lock);
  available = getConfigurationOptionValue(sock,
					  "LOAD",
					  "MAXNETDOWNBPSTOTAL");
  if (available == NULL)
    return SYSERR; 
  band = atol(available) * dtime / cronSECONDS;
  FREE(available);
  total -= ltotal;
  noise -= lnoise;
  queries -= lqueries;
  content -= lcontent;
  if (band <= 0) {
    data[0][0] = 0.0;
    data[0][1] = 0.0;
    data[0][2] = 0.0;
    data[0][3] = 0.0;
    return OK;
  }
  data[0][0] = 0.8 * noise / band; /* red */
  data[0][1] = 0.8 * (content+noise) / band; /* green */
  data[0][2] = 0.8 * (queries+content+noise) / band; /* yellow */
  data[0][3] = 0.8 * total / band; /* blue */
  /*printf("I: %f %f %f\n", 
	 data[0][0],
	 data[0][1],
	 data[0][2]);*/

  return OK;
}


  static int getTrafficSendStats(GNUNET_TCP_SOCKET * sock,
			       const void * closure,
			       gfloat ** data) {
  long long total;
  long long noise;
  long long content;
  long long queries;
  long long ltotal;
  long long lnoise;
  long long lcontent;
  long long lqueries;
  long long band;
  long long tmp;
  long long ltmp;
  cron_t dtime;
  char * available;
  char * buffer;
  int i;

  MUTEX_LOCK(&lock);
  if (OK != getStatValue(&total,	
			 &ltotal,
			 &dtime,
			 sock,
			 _("# encrypted bytes sent")))
    return SYSERR;
  if (OK != getStatValue(&noise,
			 &lnoise,
			 NULL,
			 sock,
			 _("# bytes noise sent")))
    return SYSERR;
  i = 0;
  content = lcontent = 0;
  buffer = MALLOC(512);
  while (afs_protocol_messages_content[i] != 0) {
    SNPRINTF(buffer, 
	     512,
	     _("# bytes transmitted of type %d"),
	     afs_protocol_messages_content[i++]);
    if (OK == getStatValue(&tmp,
			   &ltmp,
			   NULL,
			   sock,
			   buffer)) {
      content += tmp;
      lcontent += ltmp;
    }
  }
  i = 0;
  while (afs_protocol_messages_queries[i] != 0) {
    SNPRINTF(buffer, 
	     512,
	     _("# bytes received of type %d"),
	     afs_protocol_messages_queries[i++]);
    if (OK == getStatValue(&tmp,
			   &ltmp,
			   NULL,
			   sock,
			   buffer)) {
      queries += tmp;
      lqueries += ltmp;
    }
  }
  FREE(buffer);
  MUTEX_UNLOCK(&lock);
  available = getConfigurationOptionValue(sock,
					  "LOAD",
					  "MAXNETUPBPSTOTAL");
  if (available == NULL)
    return SYSERR;
  band = atol(available) * dtime / cronSECONDS;
  FREE(available);
  total -= ltotal;
  noise -= lnoise;
  queries -= lqueries;
  content -= lcontent;
  if (band <= 0) {
    data[0][0] = 0.0;
    data[0][1] = 0.0;
    data[0][2] = 0.0;
    data[0][3] = 0.0;
    return OK;
  }
  data[0][0] = 0.8 * noise / band; /* red */
  data[0][1] = 0.8 * (noise + content) / band; /* green */
  data[0][2] = 0.8 * (noise + content + queries) / band; /* yellow */
  data[0][3] = 0.8 * total / band; /* yellow */
  /* printf("O: %f %f %f\n", 
     data[0][0],
     data[0][1],
	 data[0][2]);*/
  
  return OK;
}



typedef struct SE_ {
  char * paneName;
  char * frameName;
  UpdateData getData;
  void * get_closure;
  unsigned int count;
  int fill; /* YES / NO */
} StatEntry;

#define STATS_COUNT 4

static StatEntry stats[] = {
  { 
    gettext_noop("Connectivity"),
    gettext_noop("# connected nodes (100% = connection table size)"),
    &getConnectedNodesStat,
    NULL,
    1,
    NO,
  }, 
  { 
    gettext_noop("CPU load"),
    gettext_noop("CPU load (in percent of allowed load)"),
    &getCPULoadStat,
    NULL,
    1,
    NO,
  },
  { 
    gettext_noop("Inbound Traffic"),
    gettext_noop("Noise (red), Content (green), Queries (yellow), other (blue)"),
    &getTrafficRecvStats,
    NULL,
    4,
    YES,
  },
  { 
    gettext_noop("Outbound Traffic"),
    gettext_noop("Noise (red), Content (green), Queries (yellow), other (blue)"),
    &getTrafficSendStats,
    NULL,
    4,
    YES,
  },
  {
    NULL,
    NULL,
    NULL,
    NULL,
    1,
    NO,
  },
};


/**
 * Remove the active page from the notebook.
 */
static void statClose(void) {
  gint pagenr;

  pagenr = gtk_notebook_get_current_page(notebook);
  gtk_notebook_remove_page(notebook, pagenr);
  /* Need to refresh the widget --
     This forces the widget to redraw itself. */
  gtk_widget_draw(GTK_WIDGET(notebook), NULL);
}

static GtkItemFactoryEntry statWindowMenu[] = {
  { 
    gettext_noop("/Close display"),   
    NULL, 
    statClose, 
    0, 
    "<Item>" 
  }
};
static gint statWindowMenuItems 
  = sizeof (statWindowMenu) / sizeof (statWindowMenu[0]);


/**
 */
static void addClosePopupMenu(GtkWidget * widget) {
  GtkWidget * menu;
  GtkItemFactory * popupFactory;

  popupFactory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>",
				      NULL);
  gtk_item_factory_create_items(popupFactory,
  				statWindowMenuItems,
				statWindowMenu,
				NULL);
  menu = gtk_item_factory_get_widget(popupFactory, "<main>");
  gtk_signal_connect(GTK_OBJECT(widget),
		     "button_press_event",
		     GTK_SIGNAL_FUNC(popupCallback),
		     menu); 
}


typedef struct {
  gint type;
  guint count;
  guint speed;
  guint draw_width, draw_height;
  guint num_points; 
  guint allocated;  
  GdkColor *colors;
  gfloat **data, **odata;
  guint data_size;
  gint colors_allocated;
  GtkWidget *main_widget;
  GtkWidget *disp;
  GtkWidget *label;
  GdkPixmap *pixmap;
  GdkGC *gc;
  int timer_index;  
  gboolean draw;
  GNUNET_TCP_SOCKET * sock;
  int statIdx;
} LoadGraph;

#define MAX_COLOR 4

typedef struct {
  gint            graph_update_interval;
  GdkColor        bg_color;
  GdkColor        frame_color;
  GdkColor        mem_color[MAX_COLOR];
} ProcConfig;

typedef struct ProcData {
  ProcConfig      config;
  LoadGraph       *mem_graph;
  int statIdx;
} ProcData;

#define GNOME_PAD_SMALL 2
#define FRAME_WIDTH 0


/**
 * Redraws the backing pixmap for the load graph and updates the window 
 */
static void load_graph_draw(LoadGraph *g) {
  guint i;
  guint j;
  gint dely;
  float delx;
  
  if (!g->disp->window)
    return;
  
  g->draw_width = g->disp->allocation.width;
  g->draw_height = g->disp->allocation.height;
  
  if (!g->pixmap)
    g->pixmap = gdk_pixmap_new (g->disp->window,
				g->draw_width, g->draw_height,
				gtk_widget_get_visual (g->disp)->depth);
  
  /* Create GC if necessary. */
  if (!g->gc) {
    g->gc = gdk_gc_new (g->disp->window);
    gdk_gc_copy (g->gc, g->disp->style->white_gc);
  }
  
  /* Allocate colors. */
  if (!g->colors_allocated) {
    GdkColormap *colormap;
    
    colormap = gdk_window_get_colormap (g->disp->window);
    for (i=0;i<2+g->count;i++) 
      gdk_color_alloc (colormap, &(g->colors [i]));    
    
    g->colors_allocated = 1;
  }
  /* Erase Rectangle */
  gdk_gc_set_foreground (g->gc, &(g->colors [0]));
  gdk_draw_rectangle (g->pixmap,
		      g->gc,
		      TRUE, 0, 0,
		      g->disp->allocation.width,
		      g->disp->allocation.height);
  
  /* draw frame */
  gdk_gc_set_foreground (g->gc, &(g->colors [1]));
  gdk_draw_rectangle (g->pixmap,
		      g->gc,
		      FALSE, 0, 0,
		      g->draw_width,
		      g->disp->allocation.height);
  
  dely = g->draw_height / 5;
  for (i = 1; i <5; i++) {
    gint y1 = g->draw_height + 1 - i * dely;
    gdk_draw_line (g->pixmap, g->gc,
		   0, y1, g->draw_width, y1);
  }
  
  gdk_gc_set_line_attributes (g->gc, 2, GDK_LINE_SOLID, GDK_CAP_ROUND, GDK_JOIN_MITER );
  delx = (float)g->draw_width / ( g->num_points - 1);
  
  for (j=0;j<g->count;j++) {
    gdk_gc_set_foreground (g->gc, &(g->colors [j + 2]));
    for (i = 0; i < g->num_points - 1; i++) {    
      gint x1 = i * delx;
      gint x2 = (i + 1) * delx;
      gint y1 = g->data[i][j] * g->draw_height - 1;
      gint y2 = g->data[i+1][j] * g->draw_height - 1;
      
      if ((g->data[i][j] != -1) && (g->data[i+1][j] != -1)) {
	if (stats[g->statIdx].fill == NO) {
	  gdk_draw_line(g->pixmap, g->gc,
			g->draw_width - x2, 
			g->draw_height - y2,
			g->draw_width - x1,
			g->draw_height - y1);
	} else {
	  GdkPoint points[4];
	  
	  points[0].x = g->draw_width - x2;
	  points[0].y = g->draw_height - y2;
	  points[1].x = g->draw_width - x1;
	  points[1].y = g->draw_height - y1;
	  points[2].x = g->draw_width - x1;
	  points[3].x = g->draw_width - x2;
	  if (j == 0) {
	    points[2].y = g->draw_height;
	    points[3].y = g->draw_height;
	  } else {
	    gint ly1 = g->data[i][j-1] * g->draw_height - 1;
	    gint ly2 = g->data[i+1][j-1] * g->draw_height - 1;
	    points[2].y = g->draw_height - ly1;
	    points[3].y = g->draw_height - ly2;
	  }
	  gdk_draw_polygon(g->pixmap,
			   g->gc,
			   1,
			   points,
			   4);  
	}
      }
    }
  }

  gdk_gc_set_line_attributes (g->gc, 1, GDK_LINE_SOLID, GDK_CAP_ROUND, GDK_JOIN_MITER );
  
  gdk_draw_pixmap (g->disp->window,
		   g->disp->style->fg_gc [GTK_WIDGET_STATE(g->disp)],
		   g->pixmap,
		   0, 0,
		   0, 0,
		   g->disp->allocation.width,
		   g->disp->allocation.height);
}


/* Updates the load graph when the timeout expires */
static int load_graph_update(LoadGraph *g) {
  guint i;  
  guint j;

  for (i=0;i<g->num_points;i++)
    memcpy(g->odata[i], 
	   g->data[i],
	   g->data_size * g->count); 
  stats[g->statIdx].getData(g->sock,
			    stats[g->statIdx].get_closure,
			    g->data);
  for (i=0;i<g->num_points-1;i++)
    for (j=0;j<g->count;j++)
      g->data[i+1][j] = g->odata[i][j];  
  if (g->draw)
    load_graph_draw (g);  
  return TRUE;
}

static void load_graph_unalloc (LoadGraph *g) {
  int i;
  if (!g->allocated)
    return;
  for (i = 0; i < g->num_points; i++) {
    FREE(g->data[i]);
    FREE(g->odata[i]);
  }
  FREE(g->data);
  FREE(g->odata);
  g->data = g->odata = NULL;
  if (g->pixmap) {
    gdk_pixmap_unref(g->pixmap);
    g->pixmap = NULL;
  }
  g->allocated = FALSE;
}

static void load_graph_alloc (LoadGraph *g) {
  int i;
  int j;

  if (g->allocated)
    return;
  
  g->data = MALLOC(sizeof(gfloat *) * g->num_points);
  g->odata = MALLOC(sizeof(gfloat*) * g->num_points);
  g->data_size = sizeof (gfloat);  
  for (i = 0; i < g->num_points; i++) {
    g->data[i] = MALLOC(g->data_size * g->count);
    g->odata[i] = MALLOC(g->data_size * g->count);
  }  
  for (i=0;i<g->num_points;i++) 
    for (j=0;j<g->count;j++)
      g->data[i][j] = -1;
  g->allocated = TRUE;
}

static gint load_graph_configure(GtkWidget *widget, 
				 GdkEventConfigure *event,
				 gpointer data_ptr) {
  LoadGraph *c = (LoadGraph *) data_ptr;
  
  if (c->pixmap) {
    gdk_pixmap_unref (c->pixmap);
    c->pixmap = NULL;
  }
  
  if (!c->pixmap)
    c->pixmap = gdk_pixmap_new (widget->window,
				widget->allocation.width,
				widget->allocation.height,
				gtk_widget_get_visual (c->disp)->depth);
  gdk_draw_rectangle (c->pixmap,
		      widget->style->black_gc,
		      TRUE, 0,0,
		      widget->allocation.width,
		      widget->allocation.height);
  gdk_draw_pixmap (widget->window,
		   c->disp->style->fg_gc [GTK_WIDGET_STATE(widget)],
		   c->pixmap,
		   0, 0,
		   0, 0,
		   c->disp->allocation.width,
		   c->disp->allocation.height);  

  load_graph_draw (c); 
  return TRUE;
}

static gint load_graph_expose(GtkWidget *widget,
			      GdkEventExpose *event,
			      gpointer data_ptr) {
  LoadGraph *g = (LoadGraph *) data_ptr;
  
  gdk_draw_pixmap (widget->window,
		   widget->style->fg_gc [GTK_WIDGET_STATE(widget)],
		   g->pixmap,
		   event->area.x, event->area.y,
		   event->area.x, event->area.y,
		   event->area.width, event->area.height);
  return FALSE;
}

static void load_graph_stop (LoadGraph *g) {
  if (g->timer_index != -1) {
    gtk_timeout_remove (g->timer_index);
    g->timer_index = -1;
  }
  if (!g)
    return;
  g->draw = FALSE;
}

static void load_graph_destroy(GtkWidget *widget, 
			       gpointer data_ptr) {
  LoadGraph *g = (LoadGraph *) data_ptr;  
  load_graph_stop(g);  
  if (g->timer_index != -1)
    gtk_timeout_remove (g->timer_index);
  if (g->sock != NULL)
    releaseClientSocket(g->sock);
  load_graph_unalloc(g);
  FREE(g->colors);
  FREE(g);
}

static LoadGraph * load_graph_new(ProcData *procdata) {
  LoadGraph *g;
  unsigned int i;

  if ( (procdata->statIdx < 0) ||
       (procdata->statIdx >= STATS_COUNT) ) {
    BREAK();
    return NULL;
  }
  if (stats[procdata->statIdx].count > MAX_COLOR) {
    BREAK();
    return NULL;
  }
  
  g = MALLOC(sizeof(LoadGraph));
  g->sock = getClientSocket();
  g->statIdx = procdata->statIdx;
  g->count = stats[g->statIdx].count;
  g->speed = procdata->config.graph_update_interval;
  g->num_points = 600;
  g->colors = MALLOC(sizeof(GdkColor) * (2+g->count));
  g->colors[0] = procdata->config.bg_color;
  g->colors[1] = procdata->config.frame_color;  
  for (i=0;i<g->count;i++) 
    g->colors[2+i] = procdata->config.mem_color[i];
  g->timer_index = -1;
  g->draw = FALSE;
  g->main_widget = gtk_vbox_new (FALSE, FALSE);
  gtk_widget_show (g->main_widget);
  g->disp = gtk_drawing_area_new();
  gtk_widget_show (g->disp);
  gtk_signal_connect (GTK_OBJECT (g->disp),
		      "expose_event",
		      GTK_SIGNAL_FUNC (load_graph_expose), g);
  gtk_signal_connect (GTK_OBJECT(g->disp), 
		      "configure_event",
		      GTK_SIGNAL_FUNC (load_graph_configure), g);
  gtk_signal_connect (GTK_OBJECT(g->disp),
		      "destroy",
		      GTK_SIGNAL_FUNC (load_graph_destroy), g); 
  gtk_widget_add_events(g->disp, GDK_EXPOSURE_MASK | GDK_BUTTON_PRESS_MASK);
  gtk_box_pack_start(GTK_BOX (g->main_widget), g->disp, TRUE, TRUE, 0);
  load_graph_alloc(g);  
  gtk_widget_show_all (g->main_widget);  
  g->timer_index = gtk_timeout_add(g->speed,
				   (GtkFunction) load_graph_update, g);
  
  return g;
}

static void load_graph_start(LoadGraph *g) {
  if (!g)
    return;
  
  if (g->timer_index == -1)
    g->timer_index = gtk_timeout_add(g->speed,
				     (GtkFunction) load_graph_update, g);
  
  g->draw = TRUE;
}

static GtkWidget * create_sys_view(ProcData * procdata) {
  GtkWidget * mem_frame;
  LoadGraph * mem_graph;

  mem_graph = load_graph_new(procdata);
  procdata->mem_graph = mem_graph;
  if (mem_graph == NULL)
    return NULL; /* oops */
  mem_frame = gtk_frame_new(_(stats[procdata->statIdx].frameName));
  gtk_container_add(GTK_CONTAINER(mem_frame),
		    mem_graph->main_widget);
  gtk_container_set_border_width(GTK_CONTAINER(mem_graph->main_widget),
				 GNOME_PAD_SMALL);
  gtk_container_set_border_width (GTK_CONTAINER(mem_frame),
				  GNOME_PAD_SMALL);
  gtk_widget_show(mem_frame);
  addClosePopupMenu(mem_frame);
  return mem_frame;
}


static GtkWidget * create_main_window(int stat) {
  GtkWidget *sys_box;
  ProcData procdata;

    
  memset(&procdata, 0, sizeof(ProcData));
  procdata.config.graph_update_interval 
    = UPDATE_INTERVAL / cronMILLIS;
  procdata.statIdx = stat;
  gdk_color_parse("black",
		  &procdata.config.bg_color);
  gdk_color_parse("gray",
		  &procdata.config.frame_color);
  gdk_color_parse("red",
		  &procdata.config.mem_color[0]);
  gdk_color_parse("green",
		  &procdata.config.mem_color[1]);
  gdk_color_parse("yellow",
		  &procdata.config.mem_color[2]);
  gdk_color_parse("blue",
		  &procdata.config.mem_color[3]);
  GNUNET_ASSERT(MAX_COLOR == 4);
  sys_box = create_sys_view(&procdata);
  if (sys_box == NULL)
    return NULL;
  load_graph_start(procdata.mem_graph); 
  return sys_box;
}


/**
 * Display the statistics.
 */
void displayStatistics(GtkWidget * widget,
		       gpointer data) {
  int dptr;
  GtkWidget * wid;

  dptr = (int) data;
  if ( (dptr < 0) ||
       (dptr >= STATS_COUNT) ) {
    BREAK();
  } else {    
    wid = create_main_window(dptr);
    if (wid != NULL)
      addToNotebook(_(stats[dptr].paneName),
		    wid);
  }
}

void initGTKStatistics() {
  MUTEX_CREATE_RECURSIVE(&lock);
}

void doneGTKStatistics() {
  unsigned int i;
  for (i=0;i<lsv_size;i++)
    FREE(lastStatValues[i].statName);
  GROW(lastStatValues,
       lsv_size,
       0);
  MUTEX_DESTROY(&lock);
}

 
/* end of statistics.c */
