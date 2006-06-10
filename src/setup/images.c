/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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

/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 * Released under the terms of the GNU GPL v2.0.
 */

/**
 * @brief GNUnet Setup
 * @file conf/images.c
 * @author Roman Zippel
 * @author Nils Durner
 */

#ifdef USE_XPM_LOAD
static const char *xpm_load[] = {
"22 22 5 1",
". c None",
"# c #000000",
"c c #838100",
"a c #ffff00",
"b c #ffffff",
"......................",
"......................",
"......................",
"............####....#.",
"...........#....##.##.",
"..................###.",
".................####.",
".####...........#####.",
"#abab##########.......",
"#babababababab#.......",
"#ababababababa#.......",
"#babababababab#.......",
"#ababab###############",
"#babab##cccccccccccc##",
"#abab##cccccccccccc##.",
"#bab##cccccccccccc##..",
"#ab##cccccccccccc##...",
"#b##cccccccccccc##....",
"###cccccccccccc##.....",
"##cccccccccccc##......",
"###############.......",
"......................"};
#endif

#ifdef USE_XPM_SAVE
static const char *xpm_save[] = {
"22 22 5 1",
". c None",
"# c #000000",
"a c #838100",
"b c #c5c2c5",
"c c #cdb6d5",
"......................",
".####################.",
".#aa#bbbbbbbbbbbb#bb#.",
".#aa#bbbbbbbbbbbb#bb#.",
".#aa#bbbbbbbbbcbb####.",
".#aa#bbbccbbbbbbb#aa#.",
".#aa#bbbccbbbbbbb#aa#.",
".#aa#bbbbbbbbbbbb#aa#.",
".#aa#bbbbbbbbbbbb#aa#.",
".#aa#bbbbbbbbbbbb#aa#.",
".#aa#bbbbbbbbbbbb#aa#.",
".#aaa############aaa#.",
".#aaaaaaaaaaaaaaaaaa#.",
".#aaaaaaaaaaaaaaaaaa#.",
".#aaa#############aa#.",
".#aaa#########bbb#aa#.",
".#aaa#########bbb#aa#.",
".#aaa#########bbb#aa#.",
".#aaa#########bbb#aa#.",
".#aaa#########bbb#aa#.",
"..##################..",
"......................"};
#endif

#ifdef USE_XPM_BACK
static const char *xpm_back[] = {
"22 22 3 1",
". c None",
"# c #000083",
"a c #838183",
"......................",
"......................",
"......................",
"......................",
"......................",
"...........######a....",
"..#......##########...",
"..##...####......##a..",
"..###.###.........##..",
"..######..........##..",
"..#####...........##..",
"..######..........##..",
"..#######.........##..",
"..########.......##a..",
"...............a###...",
"...............###....",
"......................",
"......................",
"......................",
"......................",
"......................",
"......................"};
#endif

#ifdef USE_XPM_TREE_VIEW
static const char *xpm_tree_view[] = {
"22 22 2 1",
". c None",
"# c #000000",
"......................",
"......................",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......########........",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......########........",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......########........",
"......................",
"......................"};
#endif

#ifdef USE_XPM_SINGLE_VIEW
static const char *xpm_single_view[] = {
"22 22 2 1",
". c None",
"# c #000000",
"......................",
"......................",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"......................",
"......................"};
#endif

#ifdef USE_XPM_SPLIT_VIEW
static const char *xpm_split_view[] = {
"22 22 2 1",
". c None",
"# c #000000",
"......................",
"......................",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......................",
"......................"};
#endif

#ifdef USE_XPM_SYMBOL_NO
static const char *xpm_symbol_no[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .......... ",
"            "};
#endif

#ifdef USE_XPM_SYMBOL_MOD
static const char *xpm_symbol_mod[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" .        . ",
" .   ..   . ",
" .  ....  . ",
" .  ....  . ",
" .   ..   . ",
" .        . ",
" .        . ",
" .......... ",
"            "};
#endif

#ifdef USE_XPM_SYMBOL_YES
static const char *xpm_symbol_yes[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" .        . ",
" .      . . ",
" .     .. . ",
" . .  ..  . ",
" . ....   . ",
" .  ..    . ",
" .        . ",
" .......... ",
"            "};
#endif

#ifdef USE_XPM_CHOICE_NO
static const char *xpm_choice_no[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
"    ....    ",
"  ..    ..  ",
"  .      .  ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
"  .      .  ",
"  ..    ..  ",
"    ....    ",
"            "};
#endif

#ifdef USE_XPM_CHOICE_YES
static const char *xpm_choice_yes[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
"    ....    ",
"  ..    ..  ",
"  .      .  ",
" .   ..   . ",
" .  ....  . ",
" .  ....  . ",
" .   ..   . ",
"  .      .  ",
"  ..    ..  ",
"    ....    ",
"            "};
#endif

#ifdef USE_XPM_MENU
static const char *xpm_menu[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" . ..     . ",
" . ....   . ",
" . ...... . ",
" . ...... . ",
" . ....   . ",
" . ..     . ",
" .        . ",
" .......... ",
"            "};
#endif

#ifdef USE_XPM_MENU_INV
static const char *xpm_menu_inv[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .......... ",
" ..  ...... ",
" ..    .... ",
" ..      .. ",
" ..      .. ",
" ..    .... ",
" ..  ...... ",
" .......... ",
" .......... ",
"            "};
#endif

#ifdef USE_XPM_MENUBACK
static const char *xpm_menuback[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" .     .. . ",
" .   .... . ",
" . ...... . ",
" . ...... . ",
" .   .... . ",
" .     .. . ",
" .        . ",
" .......... ",
"            "};
#endif

#if USE_XPM_VOID
static const char *xpm_void[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            "};
#endif

#if USE_MINUS_XPM
static const char * minus_xpm[] = {
"9 9 36 1",
"   c None",
".  c #B0C2D3",
"+  c #7898B5",
"@  c #FFFFFF",
"#  c #FCFCFB",
"$  c #FDFDFB",
"%  c #FCFCFA",
"&  c #F7F6F3",
"*  c #F7F7F5",
"=  c #F7F7F4",
"-  c #F6F6F4",
";  c #F1F0EB",
">  c #E5E1DA",
",  c #F5F5F1",
"'  c #000000",
")  c #DFDBD2",
"!  c #F2F2EE",
"~  c #F0F0EC",
"{  c #EDEDE7",
"]  c #ECEBE6",
"^  c #EAE9E3",
"/  c #E3E0D9",
"(  c #DBD6CC",
"_  c #E4E1D9",
":  c #DCD8CF",
"<  c #D8D3C9",
"[  c #D7D2C7",
"}  c #D6D1C6",
"|  c #D2CCC0",
"1  c #CFC8BB",
"2  c #D2CCBF",
"3  c #C6BEAE",
"4  c #C2B8A8",
"5  c #C1B8A7",
"6  c #C0B7A6",
"7  c #C3BAAA",
".+++++++.",
"+@@@@@@@+",
"+#$$$#%&+",
"+**==-;>+",
"+,''''')+",
"+!~{]^/(+",
"+_:<[}|1+",
"+2345567+",
".+++++++."};
#endif

#if USE_PLUS_XPM
static const char * plus_xpm[] = {
"9 9 34 1",
"   c None",
".  c #B0C2D3",
"+  c #7898B5",
"@  c #FFFFFF",
"#  c #FCFCFB",
"$  c #FDFDFB",
"%  c #000000",
"&  c #FCFCFA",
"*  c #F7F6F3",
"=  c #F7F7F5",
"-  c #F7F7F4",
";  c #F6F6F4",
">  c #F1F0EB",
",  c #E5E1DA",
"'  c #F5F5F1",
")  c #DFDBD2",
"!  c #F2F2EE",
"~  c #F0F0EC",
"{  c #EDEDE7",
"]  c #EAE9E3",
"^  c #E3E0D9",
"/  c #DBD6CC",
"(  c #E4E1D9",
"_  c #DCD8CF",
":  c #D8D3C9",
"<  c #D6D1C6",
"[  c #D2CCC0",
"}  c #CFC8BB",
"|  c #D2CCBF",
"1  c #C6BEAE",
"2  c #C2B8A8",
"3  c #C1B8A7",
"4  c #C0B7A6",
"5  c #C3BAAA",
".+++++++.",
"+@@@@@@@+",
"+#$$%#&*+",
"+==-%;>,+",
"+'%%%%%)+",
"+!~{%]^/+",
"+(_:%<[}+",
"+|123345+",
".+++++++."};

#endif
