AC_DEFUN([AC_CHECK_LIBWWW],
 [

if test "$needs_libwww" = no; then
  LDLIBWWW=
  LIBWWWCPPFLAGS=
  LIBWWWDEP=
else
  OLD_LIBS=$LIBS

  LibWWW_headers="WWWLib.h WWWApp.h WWWFile.h WWWHTTP.h WWWMIME.h WWWNews.h WWWTrans.h"
  LibWWW_config_h="wwwconf.h"
  libwww_include_list="${libwww_include} ${libwww_dir} \
    ${libwww_dir}/include ${libwww_dir}/Library/src"
  libwww_libdir_list="${libwww_library_dir} ${libwww_dir} ${libwww_dir}/lib \
    ${libwww_dir}/Library/src"

  if test $try_system_wwwlib = yes; then
    test -z "$libwww_config" && libwww_config=libwww-config

    # can we find the $libwww_config program?
    LIBWWW_CONFIG=
    if test -f "$libwww_config"; then
      LIBWWW_CONFIG=$libwww_config
    else
      AC_PATH_PROG(LIBWWW_CONFIG, $libwww_config)
    fi

    if test -n "$LIBWWW_CONFIG"; then
      libwww_include_found=yes
      libwww_libdir_found=yes
      LDLIBWWW=`$libwww_config --libs`

      # te: I have seen xmlparse.h one directory above the directory given
      # by libwww-config. Therefore, this hack:
      libwww_config_cflags=`$libwww_config --cflags`
      hack=`echo $libwww_config_cflags | sed 's@-I@@; s@/w3c-libwww.*@@'`
      test -n "$hack" && test -f "$hack/xmlparse.h" \
        && libwww_config_cflags="$libwww_config_cflags -I$hack"

      LIBWWWCPPFLAGS="$libwww_config_cflags -DHAVE_LIBWWW -DHAVE_WWWLIB_H"
    else
      libwww_include_found=no
      libwww_libdir_found=no
      for d in $libwww_include_list; do
        ok=yes
        for h in $LibWWW_headers; do
          if test ! -f $d/$h; then
            ok=no
            break
          fi
        done
        if test $ok = yes; then
          libwww_include=$d
          libwww_include_found=yes
          break
        fi
      done

      if test $libwww_include_found = yes; then
        LIBWWWCPPFLAGS="-I${libwww_include} -DHAVE_LIBWWW -DHAVE_WWWLIB_H"
      else
        LIBWWWCPPFLAGS="-DHAVE_LIBWWW -DHAVE_WWWLIB_H"
        if test $try_system_wwwlib = yes; then
          libwww_include_found=yes
          AC_CHECK_HEADERS($LibWWW_headers,, libwww_include_found=no; break )
        fi
      fi

      # only check for libwww.a if the includes could be found
      if test $libwww_include_found = yes; then
        for d in $libwww_libdir_list; do
          if test -f $d/libwww.a; then
            libwww_libdir=$d
            libwww_libdir_found=yes
          fi
        done

        if test ${libwww_libdir_found} = yes; then
          LDLIBWWW="-L${libwww_libdir} -lwww"
        else
          LDLIBWWW=-lwww
          libwww_libdir_found=yes
          AC_CHECK_LIB(www, HTParse,, libwww_libdir_found=no)
        fi
      fi
    fi
  fi

  if test "${libwww_include_found}" != yes ||
    test "${libwww_libdir_found}" != yes; then
    AC_MSG_ERROR([GNUnet requires libwww])
  fi
  LIBS=$OLD_LIBS
fi

AC_SUBST(LDLIBWWW)
AC_SUBST(LIBWWWCPPFLAGS)
AC_SUBST(LIBWWWDEP)

])