#!/bin/bash

#
# A script to build GNUnet.framework for Mac OS X
#
# Copyright (C) 2008 Heikki Lindholm
#
# Run from the GNUnet top source dir, e.g. 
# > ./contrib/macosx/build-osx-framework.sh
#
# - 64-bit archs won't build on Mac OS X 10.4 (too many missing deps)
# 
# TODO: 
#  - find a cleaner libtool workaround
#  - error checking
#

SDK=MacOSX10.4u.sdk
ORIG_SDK=/Developer/SDKs/${SDK}
EXTRACTOR_FRAMEWORK=/Library/Frameworks/Extractor.framework
LIBEXTRACTOR_BASE_DIR=${EXTRACTOR_FRAMEWORK}/Versions/2
FW_NAME=GNUnet.framework
FW_BASE_DIR=/Library/Frameworks/${FW_NAME}
BUILD_DIR=/tmp/GNUnet-build
FINAL_FW_BASE_DIR="${BUILD_DIR}/${FW_NAME}"
SDK_PATH="${BUILD_DIR}/${SDK}"
OPT_FLAGS="-O2 -g"

BUILD_ARCHS_LIST="ppc i386"
export MACOSX_DEPLOYMENT_TARGET=10.4

GNUMAKE_URL=http://ftp.gnu.org/pub/gnu/make
GNUMAKE_NAME=make-3.81
GETTEXT_URL=ftp://ftp.gnu.org/gnu/gettext
GETTEXT_NAME=gettext-0.16.1
GMP_URL=ftp://ftp.gmplib.org/pub
GMP_NAME=gmp-4.2.4
LIBGPG_ERROR_URL=ftp://ftp.gnupg.org/gcrypt/libgpg-error
LIBGPG_ERROR_NAME=libgpg-error-1.6
LIBGCRYPT_URL=ftp://ftp.gnupg.org/gcrypt/libgcrypt
LIBGCRYPT_NAME=libgcrypt-1.4.3
GUILE_URL=ftp://ftp.gnu.org/pub/gnu/guile
GUILE_NAME=guile-1.8.5

export PATH=${BUILD_DIR}/toolchain/bin:/usr/local/bin:/bin:/sbin:/usr/bin:/usr/sbin

#
# Fetch necessary packages
#

# $1 = package name
# $2 = base url
fetch_package()
{
	if ! cd contrib 
	then
		echo "missing 'contrib' dir"
		exit 1
	fi
	if [ ! -e "$1.tar.bz2" ] && [ ! -e "$1.tar.gz" ]
	then
		echo "fetching $1..."
		if ! ( curl -f -L -O --url "$2/$1.tar.bz2" )
		then
			if ! ( curl -f -L -O --url "$2/$1.tar.gz" )
			then
				echo "error fetching $1"
				exit 1
			fi
		fi
	fi
	cd ..
}

fetch_all_packages()
{
#	fetch_package "${GNUMAKE_NAME}" "${GNUMAKE_URL}"
	fetch_package "${GETTEXT_NAME}" "${GETTEXT_URL}"
	fetch_package "${GMP_NAME}" "${GMP_URL}"
	fetch_package "${LIBGPG_ERROR_NAME}" "${LIBGPG_ERROR_URL}"
	fetch_package "${LIBGCRYPT_NAME}" "${LIBGCRYPT_URL}"
	fetch_package "${GUILE_NAME}" "${GUILE_URL}"
}

# $1 = package name
# $2 = configure options
build_toolchain_package()
{
	local build_retval=0
	echo "building toolchain: $1..."
	if ! cd contrib
	then
		echo "missing 'contrib' dir"
		exit 1
	fi
	if [ -e "$1.tar.bz2" ]
	then
		if ! ( tar xjf "$1.tar.bz2" )
		then
			echo "error extracting $1"
			exit 1
		fi
	elif [ -e "$1.tar.gz" ]
	then
		if ! ( tar xzf "$1.tar.gz" )
		then
			echo "error extracting $1"
			exit 1
		fi
	else
		echo "no such package $1"
		exit 1
	fi
	CPPFLAGS="-I${BUILD_DIR}/toolchain/include"
	LDFLAGS="-L${BUILD_DIR}/toolchain/lib"
	if ! ( cd $1 && ./configure --prefix="${BUILD_DIR}/toolchain"	\
			CPPFLAGS="${CPPFLAGS}"				\
			LDFLAGS="${LDFLAGS}"				\
			$2 &&						\
		make install )
	then
		echo "error building $1 for toolchain"
		build_retval=1
	fi
	unset CPPFLAGS
	unset LDFLAGS
	rm -rf "$1"
	cd ..
	if [ $build_retval -eq 1 ] 
	then
		exit 1
	fi
}

#
# build native tools needed for building other packages
#
build_toolchain()
{
	
#	if [ ! -e "${BUILD_DIR}/toolchain/bin/make" ]
#	then
#		build_toolchain_package ${GNUMAKE_NAME} ""
#	fi

	if [ ! -e "${BUILD_DIR}/toolchain/bin/msgfmt" ]
	then
		build_toolchain_package "${GETTEXT_NAME}"	\
			"--disable-java				\
			--disable-native-java			\
			--without-emacs"
	fi
	if [ ! -e "${BUILD_DIR}/toolchain/lib/libgmp.dylib" ]
	then
		build_toolchain_package "${GMP_NAME}"	\
			"ABI=32 --enable-shared"
	fi
	if [ ! -e "${BUILD_DIR}/toolchain/bin/guile" ]
	then
		build_toolchain_package "${GUILE_NAME}"	\
			"ac_cv_lib_readline_readline=no"
	fi
}

#
# prepare SDK
#
prepare_sdk() 
{
	if [ ! -e "${BUILD_DIR}" ]
	then
		if ! ( mkdir -p "${BUILD_DIR}" )
		then
			echo "error creating build dir"
			exit 1
		fi
	fi

	if [ ! -e "${SDK_PATH}" ]
	then
		echo "copying SDK to build dir..."
		if ! ( cp -ipPR "${ORIG_SDK}" "${BUILD_DIR}" )
		then
			echo "error preparing SDK"
			exit 1
		fi
	fi

	if [ -h "${SDK_PATH}/Library/Frameworks" ]
	then
		if ! ( rm -f "${SDK_PATH}/Library/Frameworks" )
		then
			echo "error removing SDK 'Frameworks' symlink"
			exit 1
		fi
		if ! ( mkdir -p "${SDK_PATH}/Library/Frameworks" )
		then
			echo "error creating SDK 'Frameworks' directory"
			exit 1
		fi
	fi

	# copy Extractor.framework
	if [ -e "${EXTRACTOR_FRAMEWORK}" ]  
	then
		if [ ! -e "${SDK_PATH}${EXTRACTOR_FRAMEWORK}" ]
		then
			if ! ( cp -pPR "${EXTRACTOR_FRAMEWORK}" "${SDK_PATH}/Library/Frameworks/" )
			then
				echo "error copying ${EXTRACTOR_FRAMEWORK}"
				exit 1
			fi
		fi
	else
		echo "Extractor.framework required in ${EXTRACTOR_FRAMEWORK}"
		exit 1		
	fi
}

prepare_package()
{
	local prepare_retval=0
	if [ ! -e "${BUILD_DIR}/built-$1-${ARCH_NAME}" ]
	then
		if ! cd contrib 
		then
			echo "missing 'contrib' dir"
			exit 1
		fi

		if [ ! -e "$1" ]
		then
			if [ -e "$1.tar.bz2" ]
			then
				if ! ( tar xjf "$1.tar.bz2" )
				then
					echo "error extracting $1"
					prepare_retval=1
				fi
			elif [ -e "$1.tar.gz" ]
			then
				if ! ( tar xzf "$1.tar.gz" )
				then
					echo "error extracting $1"
					prepare_retval=1
				fi
			else
				echo "no such package $1"
				prepare_retval=1
			fi
		fi
		for patchfile in $( ls $1-patch-* 2> /dev/null | sort )
		do
			echo "applying $patchfile..."
			if ! ( cd $1 && cat "../$patchfile" | patch -p0 )
			then
				echo "error patching $1"
				prepare_retval=1
			fi
		done

		cd ..
		if [ $prepare_retval -eq 1 ] 
		then
			exit 1
		fi
	fi
}

# $1 = package name
# $2 = configure options
build_package()
{
	local build_retval=0
	if [ ! -e "${BUILD_DIR}/built-$1-${ARCH_NAME}" ]
	then
		echo "building $1 for ${ARCH_NAME}..."
		if ! cd contrib
		then
			echo "missing 'contrib' dir"
			exit 1
		fi
		CC="${ARCH_CC}"
		CXX="${ARCH_CXX}"
		CPPFLAGS="${ARCH_CPPFLAGS}"
		CFLAGS="${OPT_FLAGS} -no-cpp-precomp -fno-common ${ARCH_CFLAGS}"
		CXXFLAGS="${CFLAGS}"
		LDFLAGS="${ARCH_LDFLAGS}"
		if ! ( cd "$1" && ./configure CC="${CC}"		\
			CXX="${CXX}"					\
			CPPFLAGS="${CPPFLAGS}"				\
			CFLAGS="${CFLAGS}"				\
			CXXFLAGS="${CXXFLAGS}"				\
			LDFLAGS="${LDFLAGS}"				\
			$2 &&						\
			make DESTDIR="${SDK_PATH}" install &&		\
			touch "${BUILD_DIR}/built-$1-${ARCH_NAME}" )
		then
			echo "error building $1 for ${ARCH_NAME}"
			build_retval=1
			exit 1
		fi
		rm -rf "$1"
		rm -v `find "${SDK_PATH}" -name "*.la"`
		unset CC
		unset CXX
		unset CPPFLAGS
		unset CFLAGS
		unset CXXFLAGS
		unset LDFLAGS
		cd ..
		if [ $build_retval -eq 1 ] 
		then
			exit 1
		fi
	fi
}

#
# build dependencies
#
build_dependencies()
{
	prepare_package "${GETTEXT_NAME}"
	build_package "${GETTEXT_NAME}"			\
			"${ARCH_HOSTSETTING}		\
			--prefix="${FW_DIR}"		\
			--disable-shared		\
			--enable-static			\
			--disable-java			\
			--disable-native-java		\
			--without-emacs			\
			--with-libiconv-prefix=${SDK_PATH}/usr"

	prepare_package "${GMP_NAME}"
	build_package "${GMP_NAME}"			\
			"--host=none-apple-darwin	\
			--prefix="${FW_DIR}"		\
			--disable-shared		\
			--enable-static"
#	rm -v `find "${SDK_PATH}" -name "libgmp*.dylib"`
 
	prepare_package "${LIBGPG_ERROR_NAME}"
	build_package "${LIBGPG_ERROR_NAME}"		\
			"${ARCH_HOSTSETTING}		\
			--prefix="${FW_DIR}"		\
			--disable-shared		\
			--enable-static"

	prepare_package "${LIBGCRYPT_NAME}"
	build_package "${LIBGCRYPT_NAME}"		\
			"${ARCH_HOSTSETTING}		\
			--prefix="${FW_DIR}"		\
			--disable-shared		\
			--enable-static			\
			--with-gpg-error-prefix=${SDK_PATH}/${FW_DIR}"

	prepare_package "${GUILE_NAME}"
	build_package "${GUILE_NAME}"			\
			"${ARCH_HOSTSETTING}		\
			ac_cv_lib_readline_readline=no	\
			ac_cv_sys_restartable_syscalls=yes	\
			guile_cv_pthread_attr_getstack_works=no	\
			--prefix="${FW_DIR}"		\
			--disable-shared		\
			--enable-static"

}

#
# build libextractor
#
build_gnunet()
{
	local build_retval=0
	if [ ! -e "${BUILD_DIR}/built-GNUnet-${ARCH_NAME}" ]
	then
		echo "building GNUnet for ${ARCH_NAME}..."
		ARCH_LDFLAGS="-arch ${ARCH_NAME} -isysroot ${SDK_PATH} -Wl,-syslibroot,${SDK_PATH} -L${FW_DIR}/lib"
		CFLAGS="${OPT_FLAGS} -no-cpp-precomp -fPIC ${ARCH_CFLAGS}"
		CPPFLAGS="${ARCH_CPPFLAGS}"
		CXXFLAGS="${CFLAGS}"
		LDFLAGS="${ARCH_LDFLAGS}"
		if ! ( make clean && ./configure CC="${ARCH_CC}"	\
			CXX="${ARCH_CXX}"			\
			CPPFLAGS="${CPPFLAGS}"			\
			CFLAGS="${CFLAGS}"			\
			CXXFLAGS="${CXXFLAGS}"			\
			LDFLAGS="${LDFLAGS}"			\
			"${ARCH_HOSTSETTING}"			\
			gt_cv_func_gnugettext1_libintl=yes	\
			--prefix="${FW_DIR}"			\
			--enable-shared				\
			--with-extractor="${LIBEXTRACTOR_BASE_DIR}"	\
			--with-libgcrypt-prefix=${SDK_PATH}/${FW_DIR}	\
			--with-libiconv-prefix=${SDK_PATH}/usr )
		then
			build_retval=1
		fi
		# XXX unbelievably fragile!!!
		#cp ./libtool ./libtool.tmp
		#cat ./libtool.tmp | \
		#	sed "s/found=yes/found=no/g;" | \
		#	sed "s|eval depdepl=\"\$tmp\/lib\$tmp_libs.dylib\"|if test \"x\$tmp\" = \"x\/usr\/lib\" ; then\\
#eval depdepl=\"${SDK_PATH}\/\$tmp\/lib\$tmp_libs.dylib\"\\
#else\\
#eval  depdepl=\"\$tmp\/lib\$tmp_libs.dylib\"\\
#fi|g" > ./libtool
#		rm ./libtool.tmp
		# use native dictionary-builder instead of the cross-built one
#		find ./ -type f -name "Makefile" |	\
#			xargs perl -pi -w -e "s#./dictionary-builder #${BUILD_DIR}/toolchain/bin/dictionary-builder #g;"
		# add linking to libiconv where libintl is used
		find ./ -type f -name "Makefile" |	\
			xargs perl -pi -w -e "s#-lintl#-lintl -liconv#g;"
		if ! ( test $build_retval = 0 &&			\
			make DESTDIR="${SDK_PATH}" install &&		\
			touch "${BUILD_DIR}/built-GNUnet-${ARCH_NAME}" )
		then
			build_retval=1
		fi
		unset CPPFLAGS
		unset CFLAGS
		unset CXXFLAGS
		unset LDFLAGS
		if [ $build_retval -eq 1 ] 
		then
			exit 1
		fi
	fi
}

finalize_arch_build()
{
	if [ ! -e "${SDK_PATH}/${FW_BASE_DIR}-${ARCH_NAME}" ]
	then
		if ! ( mv "${SDK_PATH}/${FW_BASE_DIR}" "${SDK_PATH}/${FW_BASE_DIR}-${ARCH_NAME}" )
		then
			echo "error finalizing arch build"
			exit 1
		fi
	fi
}

create_directory_for()
{
	local dst_dir=$(dirname "$1")
	if [ ! -e "${dst_dir}" ]
	then
		echo "MKDIR ${dst_dir}"
		if ! ( mkdir -m 755 -p "${dst_dir}" )
		then
			echo "failed to create directory: ${dst_dir}"
			exit 1
		fi
		# fix dir permissions
		if ! ( chmod 0755 `find ${FINAL_FW_BASE_DIR} -type d` )
		then
			echo "error setting permissions"
			exit 1
		fi
	fi
}

install_executable_to_framework()
{
	local src_name="$1"
	local src_files=""
	local dst_file="${FINAL_FW_DIR}/${src_name}"
	for arch in $BUILD_ARCHS_LIST 
	do
		local tmpfile="${SDK_PATH}/${FW_BASE_DIR}-${arch}/${FW_VERSION_DIR}/${src_name}"
		if [ -h "${tmpfile}" ]
		then
			install_file_to_framework $1
		elif [ -f "${tmpfile}" ]
		then
			src_files="${tmpfile} ${src_files}"
		else
			echo "no such file: ${tmpfile}"
			exit 1
		fi
	done
	if [ "x${src_files}" != "x" ]
	then
		create_directory_for "${dst_file}"
		if [ ! -e "${dst_file}" ] && [ ! -h "${dst_file}" ]
		then
			echo "LIPO ${dst_file}"
			if ! ( lipo -create -o "${dst_file}" ${src_files} )
			then
				echo "error creating fat binary"
				exit 1
			fi
			if ! ( chmod 0755 "${dst_file}" )
			then
				echo "error settings permissions"
				exit 1
			fi
		fi
	fi
}

install_file_to_framework()
{
	local src_name="$1"
	for arch in $BUILD_ARCHS_LIST 
	do
		local src_file="${SDK_PATH}/${FW_BASE_DIR}-${arch}/${FW_VERSION_DIR}/${src_name}"
		local dst_file="${FINAL_FW_DIR}/${src_name}"
		create_directory_for "${dst_file}"
		if [ ! -e "${dst_file}" ] && [ ! -h "${dst_file}" ]
		then
			if [ -h "${src_file}" ]
			then
				echo "CP ${dst_file}"
				if ! ( cp -PpR "${src_file}" "${dst_file}" )
				then
					echo "error copying file"
					exit 1
				fi
				if ! ( chmod 0755 "${dst_file}" )
				then
					echo "error setting permissions"
					exit 1
				fi
			elif [ -f "${src_file}" ]
			then
				echo "INSTALL ${dst_file}"
				if ! ( install -m 0644 "${src_file}" "${dst_file}" )
				then
					echo "error installing file"
					exit 1
				fi
			else
				echo "no such file: ${src_file}"
				exit 1
			fi
		else
			if [ -f "${src_file}" ] && [ ! -h "${src_file}" ] && [ -f "${dst_file}" ] && [ ! -h "${dst_file}" ]
			then
				diff -q "${src_file}" "${dst_file}"
			fi
		fi
	done
}

copy_file_to_framework()
{
	local src_file="$1"
	local dst_file="${FINAL_FW_DIR}/$2"
	if [ ! -e "$dst_file" ]
	then
		create_directory_for "$dst_file"
		if ! ( install -m 0644 "$src_file" "$dst_file" )
		then
			echo "error installing file"
			exit 1
		fi
	fi
}

make_framework_link()
{
	local link_target="$1"
	local link_name="$2"
	echo "LN $link_name"
	if ! ( cd "${FINAL_FW_DIR}" && ln -sf "$link_target" "$link_name" )
	then
		echo "error creating link"
		exit 1
	fi
}

make_framework_version_links()
{
	if ! ( cd "${FINAL_FW_BASE_DIR}/Versions" && \
		ln -sf "${FW_VERSION}" "Current" && \
		cd "${FINAL_FW_BASE_DIR}" && \
		ln -sf "Versions/Current/Headers" "Headers" && \
		ln -sf "Versions/Current/Extractor" "Extractor" && \
		ln -sf "Versions/Current/PlugIns" "PlugIns" && \
		ln -sf "Versions/Current/Resources" "Resources" )
	then
		echo "error creating standard framework links"
		exit 1
	fi
}

FW_VERSION=999 
#`grep "LIB_VERSION_CURRENT=[0123456789]*" ./configure | cut -d= -f2`
FW_VERSION_DIR="Versions/${FW_VERSION}"
FW_DIR="${FW_BASE_DIR}/${FW_VERSION_DIR}"
FINAL_FW_DIR="${FINAL_FW_BASE_DIR}/${FW_VERSION_DIR}"
ORIG_DIR=$(pwd)
old_umask=$(umask)

# prepare build env
fetch_all_packages
umask 022
prepare_sdk
build_toolchain

# build deps and libextractor for all archs
for arch in $BUILD_ARCHS_LIST
do
	ARCH_NAME=$arch
	case "$arch" in
	"ppc")
		ARCH_HOSTSETTING="--host=powerpc-apple-darwin8"
		;;
	"ppc64")
		ARCH_HOSTSETTING="--host=powerpc64-apple-darwin8"
		;;
	"i386")
		ARCH_HOSTSETTING="--host=i686-apple-darwin8"
		;;
	"x86_64")
		ARCH_HOSTSETTING="--host=x86_64-apple-darwin8"
		;;
	*)
		echo "unknown architecture ${arch}"
		exit 1
		;;
	esac
	ARCH_CC="gcc -arch ${ARCH_NAME} -isysroot ${SDK_PATH}"
	ARCH_CXX="g++ -arch ${ARCH_NAME} -isysroot ${SDK_PATH}"
	ARCH_CPPFLAGS="-I${SDK_PATH}/${FW_DIR}/include -isysroot ${SDK_PATH}"
	ARCH_CFLAGS="-arch ${ARCH_NAME} -isysroot ${SDK_PATH}"
	ARCH_LDFLAGS="-L${SDK_PATH}/${FW_DIR}/lib -arch ${ARCH_NAME} -isysroot ${SDK_PATH} -Wl,-syslibroot,${SDK_PATH}"

	build_dependencies
	build_gnunet
	finalize_arch_build
done

# build framework structure
first_arch=$(echo "$BUILD_ARCHS_LIST" | cut -d ' ' -f 1)
cd "${SDK_PATH}/${FW_BASE_DIR}-${first_arch}/${FW_VERSION_DIR}"
install_executable_to_framework 'bin/remotetest'
for tfn in $(find ./bin -name 'gnunet*' -and -not -name '*.scm')
do
	install_executable_to_framework "$tfn"
done
for tfn in $(find ./bin -name 'gnunet*.scm')
do
	install_file_to_framework "$tfn"
done
for tfn in lib/libgnunet*dylib
do
	install_executable_to_framework "$tfn"
done
for tfn in lib/GNUnet/libgnunet*so
do
	install_executable_to_framework "$tfn"
done
for tfn in include/GNUnet/*
do
	install_file_to_framework "$tfn"
done
for tfn in share/GNUnet/*
do
	install_file_to_framework "$tfn"
done
for tfn in share/man/man1/gnunet*
do
	install_file_to_framework "$tfn"
done
for tfn in share/man/man5/gnunet*
do
	install_file_to_framework "$tfn"
done
for tfn in $(find ./share/locale -name 'GNUnet*')
do
	install_file_to_framework "$tfn"
done
cd "${ORIG_DIR}"
#copy_file_to_framework "./contrib/macosx/Info.plist" "Resources/Info.plist"
#copy_file_to_framework "./contrib/macosx/English.lproj/InfoPlist.strings" "Resources/English.lproj/InfoPlist.strings"
make_framework_link "lib/libgnunetutil.dylib" "GNUnet"
make_framework_link "lib" "Libraries"
make_framework_link "lib/GNUnet" "PlugIns"
make_framework_link "include" "Headers"
#make_framework_version_links

umask ${old_umask}
echo "done."
