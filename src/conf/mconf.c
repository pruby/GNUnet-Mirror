/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 * Released under the terms of the GNU GPL v2.0.
 *
 * Introduced single menu mode (show all sub-menus in one large tree).
 * 2002-11-06 Petr Baudis <pasky@ucw.cz>
 *
 * Direct use of liblxdialog library routines.
 * 2003-02-04 Petr Baudis pasky@ucw.cz
 */

/**
 * @brief GNUnet Setup
 * @file conf/mconf.c
 * @author Roman Zippel
 * @author Petr Baudis
 * @author Nils Durner
 */

#include <sys/ioctl.h>
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "mconf_dialog.h"

#define LKC_DIRECT_LINK
#include "lkc.h"

static const char menu_instructions[] =
	"Arrow keys navigate the menu.  "
	"<Enter> selects submenus --->.  "
	"Highlighted letters are hotkeys.  "
	"Pressing <Y> includes, <N> excludes features.  "
	"Press <Esc><Esc> to exit, <?> for Help.  "
	"Legend: [*] built-in  [ ] excluded  ",
radiolist_instructions[] =
	"Use the arrow keys to navigate this window or "
	"press the hotkey of the item you wish to select "
	"followed by the <SPACE BAR>. "
	"Press <?> for additional information about this option.",
inputbox_instructions_int[] =
	"Please enter a decimal value. "
	"Fractions will not be accepted.  "
	"Use the <TAB> key to move from the input field to the buttons below it.",
inputbox_instructions_hex[] =
	"Please enter a hexadecimal value. "
	"Use the <TAB> key to move from the input field to the buttons below it.",
inputbox_instructions_string[] =
	"Please enter a string value. "
	"Use the <TAB> key to move from the input field to the buttons below it.",
setmod_text[] =
	"This feature depends on another which has been configured as a module.\n"
	"As a result, this feature will be built as a module.",
nohelp_text[] =
	"There is no help available for this option.\n",
load_config_text[] =
	"Enter the name of the configuration file you wish to load.  "
	"Accept the name shown to restore the configuration you "
	"last retrieved.  Leave blank to abort.",
load_config_help[] =
	"\n"
	"For various reasons, one may wish to keep several different\n"
	"configurations available on a single machine.\n"
	"\n"
	"If you have saved a previous configuration in a file other than the\n"
	"default, entering the name of the file here will allow you\n"
	"to modify that configuration.\n"
	"\n"
	"If you are uncertain, then you have probably never used alternate\n"
	"configuration files.  You should therefor leave this blank to abort.\n",
save_config_text[] =
	"Enter a filename to which this configuration should be saved "
	"as an alternate.  Leave blank to abort.",
save_config_help[] =
	"\n"
	"For various reasons, one may wish to keep different\n"
	"configurations available on a single machine.\n"
	"\n"
	"Entering a file name here will allow you to later retrieve, modify\n"
	"and use the current configuration as an alternate to whatever\n"
	"configuration options you have selected at that time.\n"
	"\n"
	"If you are uncertain what all this means then you should probably\n"
	"leave this blank.\n",
readme_text[] = 
	"Overview\n"
	"--------\n"
	"To change a setting, highlight it with the cursor\n" 
	"keys and press <Y> to enable it or <N> to removed it.\n"
	"\n"
	"Items beginning with numbers or other text within parenthesis can\n" 
	"be changed by highlighting the item and pressing <Enter>.  Then\n"
	"enter the new value into the dialog box that pops up.\n"
	"\n"
	"\n"
	"Some additional keyboard hints:\n"
	"\n"
	"Menus\n"
	"----------\n"
	"o  Use the Up/Down arrow keys (cursor keys) to highlight the item\n" 
   	"   you wish to change or submenu wish to select and press <Enter>.\n"
   	"   Submenus are designated by \"--->\".\n"
	"\n"
   	"   Shortcut: Press the option's highlighted letter (hotkey).\n"
        "             Pressing a hotkey more than once will sequence\n"
        "             through all visible items which use that hotkey.\n"
	"\n"
   	"   You may also use the <PAGE UP> and <PAGE DOWN> keys to scroll\n"
   	"   unseen options into view.\n"
	"\n"
	"o  To exit a menu use the cursor keys to highlight the <Exit> button\n"
   	"   and press <ENTER>.\n"  
	"\n"
   	"   Shortcut: Press <ESC><ESC> or <E> or <X> if there is no hotkey\n"
        "             using those letters.  You may press a single <ESC>, but\n"
        "             there is a delayed response which you may find annoying.\n"
	"\n"
   	"   Also, the <TAB> and cursor keys will cycle between <Select>,\n"
   	"   <Exit> and <Help>\n"
	"\n"
	"o  To get help with an item, use the cursor keys to highlight <Help>\n"
  	"   and Press <ENTER>.\n"
	"\n"
   	"   Shortcut: Press <H> or <?>.\n"
	"\n"
	"\n"
	"Radiolists  (Choice lists)\n"
	"-----------\n"
	"o  Use the cursor keys to select the option you wish to set and press\n"
   	"   <S> or the <SPACE BAR>.\n"
	"\n"
   	"   Shortcut: Press the first letter of the option you wish to set then\n"
        "             press <S> or <SPACE BAR>.\n"
	"\n"
	"o  To see available help for the item, use the cursor keys to highlight\n"
   	"   <Help> and Press <ENTER>.\n"
	"\n"
   	"   Shortcut: Press <H> or <?>.\n"
	"\n"
   	"   Also, the <TAB> and cursor keys will cycle between <Select> and\n"
   	"   <Help>\n"
	"\n"
	"\n"
	"Data Entry\n"
	"-----------\n"
	"o  Enter the requested information and press <ENTER>\n"
   	"   If you are entering hexadecimal values, it is not necessary to\n"
   	"   add the '0x' prefix to the entry.\n"
	"\n"
	"o  For help, use the <TAB> or cursor keys to highlight the help option\n"
   	"   and press <ENTER>.  You can try <TAB><H> as well.\n"
	"\n"
	"\n"
	"Text Box    (Help Window)\n"
	"--------\n"
	"o  Use the cursor keys to scroll up/down/left/right.  The VI editor\n"
   	"   keys h,j,k,l function here as do <SPACE BAR> and <B> for those\n"
   	"   who are familiar with less and lynx.\n"
	"\n"
	"o  Press <E>, <X>, <Enter> or <Esc><Esc> to exit.\n"
	"\n"
	"\n"
	"Final Acceptance\n"
	"----------------\n"
	"YOUR CHANGES ARE NOT FINAL.  You will be given a last chance to\n"
	"confirm them prior to exiting Menuconfig.\n"
	"\n"
	"Alternate Configuration Files\n"
	"-----------------------------\n"
	"Menuconfig supports the use of alternate configuration files for\n"
	"those who, for various reasons, find it necessary to switch\n" 
	"between different configurations.\n"
	"\n"
	"At the end of the main menu you will find two options.  One is\n"
	"for saving the current configuration to a file of your choosing.\n"
	"The other option is for loading a previously saved alternate\n"
	"configuration.\n"
	"\n"
	"Even if you don't use alternate configuration files, but you\n" 
	"find during a Menuconfig session that you have completely messed\n"
	"up your settings, you may use the \"Load Alternate...\" option to\n"
	"restore your previously saved settings from \".config\" without\n" 
	"restarting Menuconfig.\n"
	"\n"
	"Other information\n"
	"-----------------\n"
	"If you use Menuconfig in an XTERM window make sure you have your\n" 
	"$TERM variable set to point to a xterm definition which supports color.\n"
	"Otherwise, Menuconfig will look rather bad.  Menuconfig will not\n"
	"display correctly in a RXVT window because rxvt displays only one\n"
	"intensity of color, bright.\n"
	"\n"
	"Menuconfig will display larger menus on screens or xterms which are\n"
	"set to display more than the standard 25 row by 80 column geometry.\n"
	"In order for this to work, the \"stty size\" command must be able to\n"
	"display the screen's current row and column geometry.  I STRONGLY\n"
	"RECOMMEND that you make sure you do NOT have the shell variables\n"
	"LINES and COLUMNS exported into your environment.  Some distributions\n"
	"export those variables via /etc/profile.  Some ncurses programs can\n"
	"become confused when those variables (LINES & COLUMNS) don't reflect\n"
	"the true screen size.\n"
	"\n"
	"\n"
	"******** IMPORTANT, OPTIONAL ALTERNATE PERSONALITY AVAILABLE ********\n"
	"********                                                     ********\n"
	"If you prefer to have all of the options listed in a single\n"
	"menu, rather than the default multimenu hierarchy, run the menuconfig\n"
	"with MENUCONFIG_MODE environment variable set to single_menu.\n"
	"\n"
	"Note that this mode can eventually be a little more CPU expensive\n"
	"(especially with a larger number of unrolled categories) than the\n"
	"default mode.\n"
	"*********************************************************************\n"
	"\n"
	"\n"
	"Propaganda\n"
	"----------\n"
	"The windowing support utility (lxdialog) is a VERY modified version of\n"
	"the dialog utility by Savio Lam <lam836@cs.cuhk.hk>.  Although lxdialog\n"
	"is significantly different from dialog, I have left Savio's copyrights\n"
	"intact.  Please DO NOT contact Savio with questions about lxdialog.\n"
	"He will not be able to assist.\n"
	"\n"
	"William Roadcap was the original author of Menuconfig.\n"

;

static char filename[PATH_MAX+1] = "/etc/GNUnet/.config";
static int indent;
static struct termios ios_org;
static int rows, cols;
static int child_count;
static int single_menu_mode;

static struct dialog_list_item *items[32768]; /* FIXME: This ought to be dynamic */
static int item_no;

static void conf(struct menu *menu);
static void conf_choice(struct menu *menu);
static void conf_string(struct menu *menu);
static void conf_load(void);
static void conf_save(void);
static void show_textbox(const char *title, const char *text, int r, int c);
static void show_helptext(const char *title, const char *text);
static void show_help(struct menu *menu);
static void show_readme(void);

static void init_wsize(void)
{
	struct winsize ws;
	char *env;

	if (ioctl(1, TIOCGWINSZ, &ws) == -1) {
		rows = 24;
		cols = 80;
	} else {
		rows = ws.ws_row;
		cols = ws.ws_col;
		if (!rows) {
			env = getenv("LINES");
			if (env)
				rows = atoi(env);
			if (!rows)
				rows = 24;
		}
		if (!cols) {
			env = getenv("COLUMNS");
			if (env)
				cols = atoi(env);
			if (!cols)
				cols = 80;
		}
	}

	if (rows < 19 || cols < 80) {
		end_dialog();
		fprintf(stderr, "Your display is too small to run Menuconfig!\n");
		fprintf(stderr, "It must be at least 19 lines by 80 columns.\n");
		exit(1);
	}

	rows -= 4;
	cols -= 5;
}

static void creset(void)
{
	int i;

	for (i = 0; i < item_no; i++) {
		free(items[i]->name);
		free(items[i]);
	}

	item_no = 0;
}

static void cmake(void)
{
	items[item_no] = calloc(1, sizeof(struct dialog_list_item));
	items[item_no]->name = malloc(512); items[item_no]->name[0] = 0;
	items[item_no]->namelen = 0;
	item_no++;
}

static int cprint_name(const char *fmt, ...)
{
	va_list ap;
	int res;

	if (!item_no)
		cmake();
	va_start(ap, fmt);
	res = vsnprintf(items[item_no - 1]->name + items[item_no - 1]->namelen,
			512 - items[item_no - 1]->namelen, fmt, ap);
	if (res > 0)
		items[item_no - 1]->namelen += res;
	va_end(ap);

	return res;
}

static int cset_tag(char type, void *ptr)
{
	items[item_no - 1]->type = type;
	items[item_no - 1]->data = ptr;
	return 0;
}

static void winch_handler(int sig)
{
	static int lock;

	if (!lock) {
		lock = 1;
		/* I just can't figure out how to make this thing not to crash
		 * (it won't crash everytime but at least in 1 of 10 tries).
		 * FIXME: Something rotten causes stack corruption to us, not
		 * a good thing to live with. --pasky */
#if 0
		init_wsize();
		resize_dialog(rows + 4, cols + 5);
#endif
		lock = 0;
	}
}

static void build_conf(struct menu *menu)
{
	struct symbol *sym;
	struct property *prop;
	struct menu *child;
	int type, tmp, doint = 2;
	tristate val;
	char ch;

	if (!menu_is_visible(menu))
		return;

	sym = menu->sym;
	prop = menu->prompt;
	if (!sym) {
		if (prop && menu != current_menu) {
			const char *prompt = menu_get_prompt(menu);
			switch (prop->type) {
			case P_MENU:
				child_count++;
				cmake();
				cset_tag('m', menu);

				if (single_menu_mode) {
					cprint_name("%s%*c%s",
						menu->data ? "-->" : "++>",
						indent + 1, ' ', prompt);
				} else
					cprint_name("   %*c%s  --->", indent + 1, ' ', prompt);

				if (single_menu_mode && menu->data)
					goto conf_childs;
				return;
			default:
				if (prompt) {
					child_count++;
					cmake();
					cset_tag(':', menu);
					cprint_name("---%*c%s", indent + 1, ' ', prompt);
				}
			}
		} else
			doint = 0;
		goto conf_childs;
	}

	cmake();
	type = sym_get_type(sym);
	if (sym_is_choice(sym)) {
		struct symbol *def_sym = sym_get_choice_value(sym);
		struct menu *def_menu = NULL;

		child_count++;
		for (child = menu->list; child; child = child->next) {
			if (menu_is_visible(child) && child->sym == def_sym)
				def_menu = child;
		}

		val = sym_get_tristate_value(sym);
		if (sym_is_changable(sym)) {
			cset_tag('t', menu);
			switch (type) {
			case S_BOOLEAN:
				cprint_name("[%c]", val == no ? ' ' : '*');
				break;
			case S_TRISTATE:
				switch (val) {
				case yes: ch = '*'; break;
				case mod: ch = 'M'; break;
				default:  ch = ' '; break;
				}
				cprint_name("<%c>", ch);
				break;
			}
		} else {
			cset_tag(def_menu ? 't' : ':', menu);
			cprint_name("   ");
		}

		cprint_name("%*c%s", indent + 1, ' ', menu_get_prompt(menu));
		if (val == yes) {
			if (def_menu) {
				cprint_name(" (%s)", menu_get_prompt(def_menu));
				cprint_name("  --->");
				if (def_menu->list) {
					indent += 2;
					build_conf(def_menu);
					indent -= 2;
				}
			}
			return;
		}
	} else {
		if (menu == current_menu) {
			cset_tag(':', menu);
			cprint_name("---%*c%s", indent + 1, ' ', menu_get_prompt(menu));
			goto conf_childs;
		}
		child_count++;
		val = sym_get_tristate_value(sym);
		if (sym_is_choice_value(sym) && val == yes) {
			cset_tag(':', menu);
			cprint_name("   ");
		} else {
			switch (type) {
			case S_BOOLEAN:
				cset_tag('t', menu);
				if (sym_is_changable(sym))
					cprint_name("[%c]", val == no ? ' ' : '*');
				else
					cprint_name("---");
				break;
			case S_TRISTATE:
				cset_tag('t', menu);
				switch (val) {
				case yes: ch = '*'; break;
				case mod: ch = 'M'; break;
				default:  ch = ' '; break;
				}
				if (sym_is_changable(sym))
					cprint_name("<%c>", ch);
				else
					cprint_name("---");
				break;
			default:
				cset_tag('s', menu);
				tmp = cprint_name("(%s)", sym_get_string_value(sym));
				tmp = indent - tmp + 4;
				if (tmp < 0)
					tmp = 0;
				cprint_name("%*c%s%s", tmp, ' ', menu_get_prompt(menu),
					(sym_has_value(sym) || !sym_is_changable(sym)) ?
					"" : " (NEW)");
				goto conf_childs;
			}
		}
		cprint_name("%*c%s%s", indent + 1, ' ', menu_get_prompt(menu),
			(sym_has_value(sym) || !sym_is_changable(sym)) ?
			"" : " (NEW)");
		if (menu->prompt->type == P_MENU) {
			cprint_name("  --->");
			return;
		}
	}

conf_childs:
	indent += doint;
	for (child = menu->list; child; child = child->next)
		build_conf(child);
	indent -= doint;
}

static void conf(struct menu *menu)
{
	char active_type = 0; void *active_ptr = NULL;
	const char *prompt = menu_get_prompt(menu);
	struct menu *submenu;
	struct symbol *sym;
	int stat;

	UNLINK("lxdialog.scrltmp");
	while (1) {
		indent = 0;
		child_count = 0;
		current_menu = menu;
		creset();
		build_conf(menu);
		if (!child_count)
			break;
		if (menu == &rootmenu) {
			cmake(); cset_tag(':', NULL); cprint_name("--- ");
			cmake(); cset_tag('L', NULL); cprint_name("Load an Altenatie Configuration File");
			cmake(); cset_tag('S', NULL); cprint_name("Save Configuration to an Alternate File");
		}
		dialog_clear();
		/* active_item itself can change after any creset() + 
                 * build_conf() :-( */
		stat = dialog_menu(prompt ? prompt : "Main Menu",
				menu_instructions, rows, cols, rows - 10,
				active_type, active_ptr, item_no, items);
		if (stat < -1)
			continue; /* Windows resized, let's redraw... */
		if (stat < 0)
			break;

		if (stat == 1 || stat == 255)
			break;

		{
			struct dialog_list_item *active_item;

			active_item = first_sel_item(item_no, items);
			if (!active_item)
				continue;
			active_item->selected = 0;
			active_type = active_item->type;
			active_ptr = active_item->data;
		}
		
		if (!active_type)
			continue;

		sym = NULL;
		submenu = active_ptr;
		if (submenu) sym = submenu->sym;		

		switch (stat) {
		case 0:
			switch (active_type) {
			case 'm':
				if (single_menu_mode)
					submenu->data = (void *) (long) !submenu->data;
				else
					conf(submenu);
				break;
			case 't':
				if (sym_is_choice(sym) && sym_get_tristate_value(sym) == yes)
					conf_choice(submenu);
				else if (submenu->prompt->type == P_MENU)
					conf(submenu);
				break;
			case 's':
				conf_string(submenu);
				break;
			case 'L':
				conf_load();
				break;
			case 'S':
				conf_save();
				break;
			}
			break;
		case 2:
			if (sym)
				show_help(submenu);
			else
				show_readme();
			break;
		case 3:
			if (active_type == 't') {
				if (sym_set_tristate_value(sym, yes))
					break;
				if (sym_set_tristate_value(sym, mod))
					show_textbox(NULL, setmod_text, 6, 74);
			}
			break;
		case 4:
			if (active_type == 't')
				sym_set_tristate_value(sym, no);
			break;
		case 5:
			if (active_type == 't')
				sym_set_tristate_value(sym, mod);
			break;
		case 6:
			if (active_type == 't') {
				sym_toggle_tristate_value(sym);
			} else if (active_type == 'm') {
				if (single_menu_mode)
 				        submenu->data = (void *) (long)!submenu->data;
				else
					conf(submenu);
			}
			break;
		}
	}
}

static void show_textbox(const char *title, const char *text, int r, int c)
{
	int fd;

	fd = CREAT(".help.tmp", 0777);
	WRITE(fd, text, strlen(text));
	close(fd);
	while (dialog_textbox(title, ".help.tmp", r, c) < 0)
		;
	UNLINK(".help.tmp");
}

static void show_helptext(const char *title, const char *text)
{
	show_textbox(title, text, rows, cols);
}

static void show_help(struct menu *menu)
{
	const char *help;
	char *helptext;
	struct symbol *sym = menu->sym;

	help = sym->help;
	if (!help)
		help = nohelp_text;
	if (sym->name) {
		helptext = malloc(strlen(sym->name) + strlen(help) + 16);
		sprintf(helptext, "CONFIG_%s:\n\n%s", sym->name, help);
		show_helptext(menu_get_prompt(menu), helptext);
		free(helptext);
	} else
		show_helptext(menu_get_prompt(menu), help);
}

static void show_readme(void)
{
	show_textbox(NULL, readme_text, rows, cols);
}

static void conf_choice(struct menu *menu)
{
	const char *prompt = menu_get_prompt(menu);
	struct menu *child;
	struct symbol *active;

	while (1) {
		current_menu = menu;
		active = sym_get_choice_value(menu->sym);
		creset();
		for (child = menu->list; child; child = child->next) {
			if (!menu_is_visible(child))
				continue;
			cmake();
			cset_tag(0, child);
			cprint_name("%s", menu_get_prompt(child));
			items[item_no - 1]->selected = (child->sym == active);
		}

		switch (dialog_checklist(prompt ? prompt : "Main Menu",
					radiolist_instructions, 15, 70, 6,
					item_no, items, FLAG_RADIO)) {
		case 0:
			menu = first_sel_item(item_no, items)->data;
			if (!menu)
				break;
			sym_set_tristate_value(menu->sym, yes);
			return;
		case 1:
			show_help(menu);
			break;
		case 255:
			return;
		}
	}
}

static void conf_string(struct menu *menu)
{
	const char *prompt = menu_get_prompt(menu);

	while (1) {
		char *heading;

		switch (sym_get_type(menu->sym)) {
		case S_INT:
			heading = (char *) inputbox_instructions_int;
			break;
		case S_HEX:
			heading = (char *) inputbox_instructions_hex;
			break;
		case S_STRING:
			heading = (char *) inputbox_instructions_string;
			break;
		default:
			heading = "Internal mconf error!";
			/* panic? */;
		}
		
		switch (dialog_inputbox(prompt ? prompt : "Main Menu",
			heading, 10, 75,
			sym_get_string_value(menu->sym))) {
		case 0:
			if (sym_set_string_value(menu->sym, dialog_input_result))
				return;
			show_textbox(NULL, "You have made an invalid entry.", 5, 43);
			break;
		case 1:
			show_help(menu);
			break;
		case 255:
			return;
		}
	}
}

static void conf_load(void)
{
	while (1) {
		switch(dialog_inputbox(NULL, load_config_text, 11, 55,
					filename)) {
		case 0:
			if (!dialog_input_result[0])
				return;
			if (!conf_read(dialog_input_result))
				return;
			show_textbox(NULL, "File does not exist!", 5, 38);
			break;
		case 1:
			show_helptext("Load Alternate Configuration", load_config_help);
			break;
		case 255:
			return;
		}
	}
}

static void conf_save(void)
{
	while (1) {
		switch(dialog_inputbox(NULL, save_config_text, 11, 55,
					filename)) {
		case 0:
			if (!dialog_input_result[0])
				return;
			if (!conf_write(dialog_input_result))
				return;
			show_textbox(NULL, "Can't create file!  Probably a nonexistent directory.", 5, 60);
			break;
		case 1:
			show_helptext("Save Alternate Configuration", save_config_help);
			break;
		case 255:
			return;
		}
	}
}

static void conf_cleanup(void)
{
	tcsetattr(1, TCSAFLUSH, &ios_org);
	UNLINK(".help.tmp");
	UNLINK("lxdialog.scrltmp");
}

int mconf_main(int ac, char **av)
{
	char *mode;
	int stat;
	conf_parse(av[1]);
	conf_read(NULL);

	backtitle = malloc(128);
	strcpy(backtitle, "GNUnet Configuration");

	mode = getenv("MENUCONFIG_MODE");
	if (mode) {
		if (!strcasecmp(mode, "single_menu"))
			single_menu_mode = 1;
	}

	{
		struct sigaction sa;
		sa.sa_handler = winch_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART;
		sigaction(SIGWINCH, &sa, NULL);
	}

	tcgetattr(1, &ios_org);
	atexit(conf_cleanup);
	init_dialog();
	init_wsize();
	conf(&rootmenu);

	do {
		stat = dialog_yesno(NULL,
				"Do you wish to save your new configuration?",
				5, 60);
	} while (stat < 0);
	end_dialog();

	if (stat == 0) {
		conf_write(NULL);
		printf("\n\n"
			"*** End of configuration.\n"
			"\n\n");
	} else
		printf("\n\n"
			"Your configuration changes were NOT saved."
			"\n\n");

	return 0;
}
