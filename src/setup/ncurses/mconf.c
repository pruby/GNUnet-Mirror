/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
*/

/**
 * @brief GNUnet Setup using dialog
 * @file setup/ncurses/mconf.c
 * @author Christian Grothoff
 */

#include <dialog.h>

#undef _
#undef OK
#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_setup_lib.h"

#include "mconf.h"

#ifndef MINGW
#include <termios.h>
#endif

static struct GE_Context *ectx;

static void
show_help (const char *option, const char *helptext)
{
  dialog_vars.help_button = 0;
  dialog_msgbox (option, gettext (helptext), 20, 70, TRUE);
  dialog_vars.help_button = 1;
}

static void
run_menu (struct GNS_Context *ctx,
          struct GNS_Tree *pos, struct GC_Configuration *cfg)
{
  int st;
  int i;
  DIALOG_LISTITEM *items;
  int msel;
  DIALOG_FORMITEM fitem;
  unsigned long long lval;
  double dval;
  GNS_Value *val;
  char *tmp;
  size_t tlen;

  fitem.type = 0;
  fitem.name = pos->description;
  fitem.name_len = strlen (pos->description);
  fitem.name_y = 3;
  fitem.name_x = 5;
  fitem.name_free = 0;
  fitem.text_y = 5;
  fitem.text_x = 5;
  fitem.text_flen = 55;
  fitem.text_ilen = 63;
  fitem.text_free = 0;
  fitem.help_free = 0;

  msel = 0;
  while (1)
    {
      switch (pos->type & GNS_KindMask)
        {
        case GNS_Root:
          dialog_vars.cancel_label = _("Exit");
          break;
        case GNS_Node:
          dialog_vars.cancel_label = _("Up");
          break;
        default:
          dialog_vars.cancel_label = _("Cancel");
          break;
        }
      switch (pos->type & GNS_KindMask)
        {
        case GNS_Root:
          /* fall-through! */
        case GNS_Node:
          st = 0;
          i = 0;
          while (pos->children[i] != NULL)
            {
              if (pos->children[i]->visible)
                st++;
              i++;
            }
          if (st == 0)
            return;             /* no visible entries */
          items = MALLOC (sizeof (DIALOG_LISTITEM) * st);
          i = 0;
          st = 0;
          while (pos->children[i] != NULL)
            {
              if (pos->children[i]->visible)
                {
                  items[st].name = pos->children[i]->option;
                  items[st].text = gettext (pos->children[i]->description);
                  items[st].help = gettext (pos->children[i]->help);
                  if (st == msel)
                    items[st].state = 1;
                  else
                    items[st].state = 0;
                  st++;
                }
              i++;
            }
          st = dlg_menu (gettext (pos->description),
                         "Select configuration option to change",
                         20, 70, 13, st, items, &msel, NULL);
          FREE (items);
          switch (st)
            {
            case DLG_EXIT_OK:
              i = 0;
              st = msel;
              while (pos->children[i] != NULL)
                {
                  if (pos->children[i]->visible)
                    {
                      if (st == 0)
                        run_menu (ctx, pos->children[i], cfg);
                      st--;
                    }
                  i++;
                }
              break;
            case DLG_EXIT_HELP:
              show_help (pos->children[msel]->option,
                         pos->children[msel]->help);
              break;
            case DLG_EXIT_ESC:
            case DLG_EXIT_ERROR:
            case DLG_EXIT_CANCEL:
            default:
              return;
            }
          break;

        case GNS_Leaf:
          switch (pos->type & GNS_TypeMask)
            {
            case GNS_Boolean:
              st = dialog_yesno (pos->option,
                                 gettext (pos->description), 5, 60);
              switch (st)
                {
                case DLG_EXIT_OK:
                case DLG_EXIT_CANCEL:
                  if (0 != GC_set_configuration_value_string (cfg,
                                                              ectx,
                                                              pos->section,
                                                              pos->option,
                                                              st ==
                                                              DLG_EXIT_OK ?
                                                              "YES" : "NO"))
                    {
                      show_help (pos->option,
                                 gettext_noop
                                 ("Internal error! (Choice invalid?)"));
                      break;
                    }
                  return;
                case DLG_EXIT_HELP:
                  show_help (pos->option, pos->help);
                  break;
                case DLG_EXIT_ESC:
                  return;
                default:
                  GE_BREAK (ectx, 0);
                  return;
                }
              break;
            case GNS_String:
              /* free form */
              fitem.text = MALLOC (65536);
              strcpy (fitem.text, pos->value.String.val);
              fitem.text_len = strlen (fitem.text);
              fitem.help = pos->help;
              msel = 0;
              st = dlg_form (pos->option, "", 20, 70, 15, 1, &fitem, &msel);
              switch (st)
                {
                case DLG_EXIT_OK:
                  if (0 != GC_set_configuration_value_string (cfg,
                                                              ectx,
                                                              pos->section,
                                                              pos->option,
                                                              fitem.text))
                    {
                      show_help (pos->option,
                                 gettext_noop
                                 ("Internal error! (Value invalid?)"));
                      break;
                    }
                  FREE (fitem.text);
                  return;
                case DLG_EXIT_HELP:
                  show_help (pos->option, pos->help);
                  break;
                case DLG_EXIT_CANCEL:
                case DLG_EXIT_ERROR:
                case DLG_EXIT_ESC:
                  FREE (fitem.text);
                  return;
                default:
                  break;
                }
              FREE (fitem.text);
              /* end free form */
              break;
            case GNS_SC:
              /* begin single choice */
              val = &pos->value;
              i = 0;
              while (val->String.legalRange[i] != NULL)
                i++;
              GE_ASSERT (ectx, i != 0);
              items = MALLOC (sizeof (DIALOG_LISTITEM) * i);
              i = 0;
              msel = -1;

              while (val->String.legalRange[i] != NULL)
                {
                  items[i].name = "";
                  items[i].text = val->String.legalRange[i];
                  items[i].help = "";
                  items[i].state = 0;
                  if (0 == strcmp (val->String.legalRange[i],
                                   val->String.val))
                    {
                      items[i].state = 1;
                      msel = i;
                    }
                  if ((msel == -1) &&
                      (0 == strcmp (val->String.legalRange[i],
                                    val->String.def)))
                    msel = i;
                  i++;
                }
              st = dlg_checklist (gettext (pos->option),
                                  gettext (pos->description),
                                  20,
                                  70, 13, i, items, " *", FLAG_RADIO, &msel);
              FREE (items);
              switch (st)
                {
                case DLG_EXIT_OK:
                  if (0 != GC_set_configuration_value_choice (cfg,
                                                              ectx,
                                                              pos->section,
                                                              pos->option,
                                                              val->String.
                                                              legalRange
                                                              [msel]))
                    {
                      show_help (pos->option,
                                 gettext_noop
                                 ("Internal error! (Choice invalid?)"));
                      break;
                    }
                  return;
                case DLG_EXIT_HELP:
                  show_help (pos->option, pos->help);
                  break;
                case DLG_EXIT_ESC:
                case DLG_EXIT_ERROR:
                case DLG_EXIT_CANCEL:
                default:
                  return;
                }
              break;
            case GNS_MC:
              /* begin multiple choice */
              val = &pos->value;
              i = 0;
              tlen = 2;
              while (val->String.legalRange[i] != NULL)
                i++;
              GE_ASSERT (ectx, i != 0);
              items = MALLOC (sizeof (DIALOG_LISTITEM) * i);
              i = 0;
              msel = 0;
              while (val->String.legalRange[i] != NULL)
                {
                  items[i].name = "";
                  items[i].text = val->String.legalRange[i];
                  tlen += strlen (val->String.legalRange[i]) + 1;
                  items[i].help = "";
                  items[i].state = 0;

                  tmp = val->String.val;
                  while (NULL != (tmp = strstr (tmp,
                                                val->String.legalRange[i])))
                    {
                      if (((tmp == val->String.val) ||
                           (tmp[-1] == ' ')) &&
                          ((strlen (tmp) ==
                            strlen (val->String.legalRange[i]))
                           || (tmp[strlen (val->String.legalRange[i])] ==
                               ' ')))
                        {
                          items[i].state = 1;
                          break;
                        }
                      tmp++;    /* make sure strstr advances */
                    }
                  i++;
                }
              st = dlg_checklist (gettext (pos->option),
                                  gettext (pos->description),
                                  20,
                                  70, 13, i, items, " *", FLAG_CHECK, &msel);
              switch (st)
                {
                case DLG_EXIT_OK:
                  tmp = MALLOC (tlen);
                  tmp[0] = '\0';
                  i = 0;
                  while (val->String.legalRange[i] != NULL)
                    {
                      if (items[i].state == 1)
                        {
                          strcat (tmp, items[i].text);
                          strcat (tmp, " ");
                        }
                      i++;
                    }
                  if (strlen (tmp) > 0)
                    tmp[strlen (tmp) - 1] = '\0';
                  if (0 != GC_set_configuration_value_choice (cfg,
                                                              ectx,
                                                              pos->section,
                                                              pos->option,
                                                              tmp))
                    {
                      FREE (tmp);
                      show_help (pos->option,
                                 gettext_noop
                                 ("Internal error! (Choice invalid?)"));
                      break;
                    }
                  FREE (tmp);
                  FREE (items);
                  return;
                case DLG_EXIT_HELP:
                  show_help (pos->option, pos->help);
                  break;
                case DLG_EXIT_ESC:
                case DLG_EXIT_ERROR:
                case DLG_EXIT_CANCEL:
                default:
                  FREE (items);
                  return;
                }
              FREE (items);
              break;
            case GNS_Double:
              fitem.text = MALLOC (64);
              SNPRINTF (fitem.text, 64, "%f", pos->value.Double.val);
              fitem.text_len = strlen (fitem.text);
              fitem.help = pos->help;
              st = DLG_EXIT_HELP;
              msel = 0;
              st = dlg_form (pos->option, "", 20, 70, 15, 1, &fitem, &msel);
              switch (st)
                {
                case DLG_EXIT_OK:
                  if (1 != sscanf (fitem.text, "%lf", &dval))
                    {
                      show_help (pos->option,
                                 gettext_noop
                                 ("Invalid input, expecting floating point value."));
                      break;
                    }
                  if (0 != GC_set_configuration_value_string (cfg,
                                                              ectx,
                                                              pos->section,
                                                              pos->option,
                                                              fitem.text))
                    {
                      show_help (pos->option,
                                 gettext_noop
                                 ("Internal error! (Value invalid?)"));
                      break;
                    }
                  FREE (fitem.text);
                  return;
                case DLG_EXIT_HELP:
                  show_help (pos->option, pos->help);
                  break;
                default:
                  break;
                }
              FREE (fitem.text);
              break;

            case GNS_UInt64:
              fitem.text = MALLOC (64);
              SNPRINTF (fitem.text, 64, "%llu", pos->value.UInt64.val);
              fitem.text_len = strlen (fitem.text);
              fitem.help = pos->help;
              st = DLG_EXIT_HELP;
              msel = 0;
              while (st == DLG_EXIT_HELP)
                {
                  st = dlg_form (pos->option,
                                 "", 20, 70, 15, 1, &fitem, &msel);
                  switch (st)
                    {
                    case DLG_EXIT_OK:
                      if (1 != sscanf (fitem.text, "%llu", &lval))
                        {
                          show_help (pos->option,
                                     gettext_noop
                                     ("Invalid input, expecting integer."));
                          continue;
                        }
                      if ((lval < pos->value.UInt64.min) ||
                          (lval > pos->value.UInt64.max))
                        {
                          show_help (pos->option,
                                     gettext_noop
                                     ("Value is not in legal range."));
                          continue;
                        }
                      if (0 != GC_set_configuration_value_number (cfg,
                                                                  ectx,
                                                                  pos->
                                                                  section,
                                                                  pos->option,
                                                                  lval))
                        {
                          show_help (pos->option,
                                     gettext_noop
                                     ("Internal error! (Choice invalid?)"));
                          continue;
                        }
                      break;
                    case DLG_EXIT_HELP:
                      show_help (pos->option, pos->help);
                      break;
                    default:
                      break;
                    }
                }
              FREE (fitem.text);
              return;
            default:
              GE_BREAK (ectx, 0);
              return;
            }                   /* end switch type & type */
          break;

        default:
          GE_BREAK (ectx, 0);
          break;

        }                       /* end switch type & Kind */
    }                           /* end while(1) */
}


int
mconf_mainsetup_curses (int argc,
                        const char **argv,
                        struct PluginHandle *self,
                        struct GE_Context *e,
                        struct GC_Configuration *cfg,
                        struct GNS_Context *gns,
                        const char *filename, int is_daemon)
{
  int ret;
  struct termios ios_org;

  ectx = e;
#ifndef MINGW
  tcgetattr (1, &ios_org);
#endif
  dialog_vars.backtitle = _("GNUnet Configuration");
  dialog_vars.item_help = 1;
  dialog_vars.help_button = 1;

  init_dialog (stdin, stderr);

  run_menu (gns, GNS_get_tree (gns), cfg);

  ret = 0;
  if ((0 == GC_test_dirty (cfg)) && (0 == ACCESS (filename, R_OK)))
    {
      end_dialog ();
      printf (_("Configuration unchanged, no need to save.\n"));
    }
  else
    {
      dialog_vars.help_button = 0;
      ret = dialog_yesno (NULL,
                          _("Do you wish to save your new configuration?"),
                          5, 60);
      end_dialog ();
      if (ret == DLG_EXIT_OK)
        {
          if (0 != GC_write_configuration (cfg, filename))
            {
              /* error message already printed... */
              ret = 1;
            }
          else
            {
              ret = 0;
            }
          printf (_("\nEnd of configuration.\n"));
        }
      else
        {
          ret = 0;
          printf (_("\nYour configuration changes were NOT saved.\n"));
        }
    }

#ifndef MINGW
  tcsetattr (1, TCSAFLUSH, &ios_org);
#endif
  return ret;
}
