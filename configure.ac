##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##
##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##
m4_define([v_maj], [4])
m4_define([v_min], [9])
m4_define([v_mic], [2])
##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##
m4_define([v_ver], [v_maj.v_min.v_mic])
m4_define([lt_rev], m4_eval(v_maj + v_min))
m4_define([lt_cur], v_mic)
m4_define([lt_age], v_min)
##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##
##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##

AC_INIT([cgminer], [v_ver], [support@zwilla.de])

AC_PREREQ(2.59)
AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([cgminer.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_USE_SYSTEM_EXTENSIONS

##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##
##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##
m4_ifdef([v_rev], , [m4_define([v_rev], [0])])
m4_ifdef([v_rel], , [m4_define([v_rel], [])])
AC_DEFINE_UNQUOTED(CGMINER_MAJOR_VERSION, [v_maj], [Major version])
AC_DEFINE_UNQUOTED(CGMINER_MINOR_VERSION, [v_min], [Minor version])
AC_DEFINE_UNQUOTED(CGMINER_MINOR_SUBVERSION, [v_mic], [Micro version])
version_info="lt_rev:lt_cur:lt_age"
release_info="v_rel"
AC_SUBST(version_info)
AC_SUBST(release_info)
##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##
##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##--##
VMAJ=v_maj
AC_SUBST(VMAJ)

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
gl_EARLY
AC_PROG_GCC_TRADITIONAL
AM_PROG_CC_C_O

# This breaks autoreconf so disable it
# LT_INIT([disable-shared])

gl_INIT

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(syslog.h)

AC_FUNC_ALLOCA

have_win32=false
PTHREAD_FLAGS="-lpthread"
DLOPEN_FLAGS="-ldl"
WS2_LIBS=""
MM_LIBS=""
MATH_LIBS="-lm"
RT_LIBS="-lrt"

case $target in
  amd64-*)
    have_x86_64=true
    ;;
  x86_64-*)
    have_x86_64=true
    ;;
  *)
    have_x86_64=false
    ;;
esac

case $target in
  *-*-linux-gnu*)
    have_linux=true
    ;;
  *-*-mingw*)
    have_win32=true
    PTHREAD_FLAGS=""
    DLOPEN_FLAGS=""
    WS2_LIBS="-lws2_32"
    MM_LIBS="-lwinmm"
    RT_LIBS=""
    AC_DEFINE([_WIN32_WINNT], [0x0501], "WinNT version for XP+ support")
    ;;
  powerpc-*-darwin*)
    have_darwin=true
    CFLAGS="$CFLAGS -faltivec"
    PTHREAD_FLAGS=""
    RT_LIBS=""
    ;;
  *-*-darwin*)
    have_darwin=true
    PTHREAD_FLAGS=""
    RT_LIBS=""
	;;
esac

has_winpthread=false
if test "x$have_win32" = xtrue; then
        has_winpthread=true
        AC_CHECK_LIB(winpthread, nanosleep, , has_winpthread=false)
        PTHREAD_LIBS=-lwinpthread
fi

if test "x$has_winpthread" != xtrue; then
        AC_CHECK_LIB(pthread, pthread_create, ,
                AC_MSG_ERROR([Could not find pthread library - please install libpthread]))
        PTHREAD_LIBS=-lpthread
fi

# Drivers that are designed to be run on dedicated hardware should set standalone to yes
# All drivers should prepend an x to the drivercount

bitmain="no"

AC_ARG_ENABLE([bitmain],
	[AC_HELP_STRING([--enable-bitmain],[Compile support for Bitmain Multi Chain (default disabled)])],
	[bitmain=$enableval]
	)
if test "x$bitmain" = xyes; then
	AC_DEFINE([USE_BITMAIN], [1], [Defined to 1 if Bitmain Multi Chain support is wanted])
	drivercount=x$drivercount
	standalone="yes"
fi
AM_CONDITIONAL([HAS_BITMAIN], [test x$bitmain = xyes])

bitmain_c5="no"

AC_ARG_ENABLE([bitmain_c5],
	[AC_HELP_STRING([--enable-bitmain-c5],[Compile support for Bitmain C5(default disabled)])],
	[bitmain_c5=$enableval]
	)
if test "x$bitmain_c5" = xyes; then
	AC_DEFINE([USE_BITMAIN_C5], [1], [Defined to 1 if Bitmain C5 support is wanted])
	drivercount=x$drivercount
	standalone="yes"
fi
AM_CONDITIONAL([HAS_BITMAIN_C5], [test x$bitmain_c5 = xyes])

forcecombo="no"

AC_ARG_ENABLE([forcecombo],
	[AC_HELP_STRING([--enable-forcecombo],[Allow combinations of drivers not intended to be built together(default disabled)])],
	[forcecombo=$enableval]
	)
if test "x$forcecombo" = xyes; then
	standalone="no"
fi

curses="auto"

AC_ARG_WITH([curses],
	[AC_HELP_STRING([--without-curses],[Compile support for curses TUI (default enabled)])],
	[curses=$withval]
	)
if test "x$curses" = "xno"; then
	cursesmsg='User specified --without-curses. TUI support DISABLED'
else
	AC_SEARCH_LIBS(addstr, ncurses pdcurses, [
		curses=yes
		cursesmsg="FOUND: ${ac_cv_search_addstr}"
		AC_DEFINE([HAVE_CURSES], [1], [Defined to 1 if curses TUI support is wanted])
	], [
		if test "x$curses" = "xyes"; then
			AC_MSG_ERROR([Could not find curses library - please install libncurses-dev or pdcurses-dev (or configure --without-curses)])
		else
			AC_MSG_WARN([Could not find curses library - if you want a TUI, install libncurses-dev or pdcurses-dev])
			curses=no
			cursesmsg='NOT FOUND. TUI support DISABLED'
		fi
	])
fi


#Add a new device to this list if it needs libusb, along with a no on the end.
if test x$bitmain != xno; then
	want_usbutils=true
else
	want_usbutils=false
fi

if test x$bitfury != xno; then
	want_libbitfury=true
else
	want_libbitfury=false
fi

if test x$bitmain_c5 != xno; then
	want_crc16=true
else
	want_crc16=false
fi


AM_CONDITIONAL([WANT_USBUTILS], [test x$want_usbutils != xfalse])
AM_CONDITIONAL([WANT_LIBBITFURY], [test x$want_libbitfury != xfalse])
AM_CONDITIONAL([HAVE_CURSES], [test x$curses = xyes])
AM_CONDITIONAL([HAVE_WINDOWS], [test x$have_win32 = xtrue])
AM_CONDITIONAL([HAVE_x86_64], [test x$have_x86_64 = xtrue])
AM_CONDITIONAL([WANT_CRC16], [test x$want_crc16 != xfalse])

if test "x$want_usbutils" != xfalse; then
	dlibusb="no"
	AC_DEFINE([USE_USBUTILS], [1], [Defined to 1 if usbutils support required])
	AC_ARG_WITH([system-libusb],
		[AC_HELP_STRING([--with-system-libusb],[NOT RECOMMENDED! Compile against dynamic system libusb. (Default use included static libusb)])],
		[dlibusb=$withval]
	)

	if test "x$dlibusb" != xno; then
		case $target in
			*-*-freebsd*)
				LIBUSB_LIBS="-lusb"
				LIBUSB_CFLAGS=""
				AC_DEFINE(HAVE_LIBUSB, 1, [Define if you have libusb-1.0])
				;;
			*)
				PKG_CHECK_MODULES(LIBUSB, libusb-1.0, [AC_DEFINE(HAVE_LIBUSB, 1, [Define if you have libusb-1.0])], [AC_MSG_ERROR([Could not find usb library - please install libusb-1.0])])
				;;
		esac
	else
		AC_CONFIG_SUBDIRS([compat/libusb-1.0])
		LIBUSB_LIBS="compat/libusb-1.0/libusb/.libs/libusb-1.0.a"
		if test "x$have_linux" = "xtrue"; then
			AC_ARG_ENABLE([udev],
				[AC_HELP_STRING([--disable-udev],[Disable building libusb with udev])],
				[udev=$enableval]
				)

			if test "x$udev" != xno; then
			LIBUSB_LIBS+=" -ludev"
		fi
		fi
		if test "x$have_darwin" = "xtrue"; then
			LIBUSB_LIBS+=" -lobjc"
			LDFLAGS+=" -framework CoreFoundation -framework IOKit"
		fi
	fi
else
	LIBUSB_LIBS=""
fi

AM_CONDITIONAL([WANT_STATIC_LIBUSB], [test x$dlibusb = xno])

AC_CONFIG_SUBDIRS([compat/jansson-2.6])
JANSSON_LIBS="compat/jansson-2.6/src/.libs/libjansson.a"

PKG_PROG_PKG_CONFIG()

if test "x$have_cgminer_sdk" = "xtrue"; then
	if test "x$have_x86_64" = xtrue; then
		ARCH_DIR=x86_64
	else
		ARCH_DIR=x86
	fi
	PKG_CONFIG="${PKG_CONFIG:-pkg-config} --define-variable=arch=$ARCH_DIR --define-variable=target=$target --define-variable=cgminersdkdir=$CGMINER_SDK"
	PKG_CONFIG_PATH="$CGMINER_SDK/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
fi

AC_SUBST(LIBUSB_LIBS)
AC_SUBST(LIBUSB_CFLAGS)

AC_ARG_ENABLE([libcurl],
	[AC_HELP_STRING([--disable-libcurl],[Disable building with libcurl for getwork and GBT support])],
	[libcurl=$enableval]
	)

if test "x$libcurl" != xno; then
	if test "x$have_win32" != xtrue; then
		PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.25.0], [AC_DEFINE([CURL_HAS_KEEPALIVE], [1], [Defined if version of curl supports keepalive.])],
			[PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.18.2], ,[AC_MSG_ERROR([Missing required libcurl dev >= 7.18.2])])])
	else
		PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.25.0], ,[AC_MSG_ERROR([Missing required libcurl dev >= 7.25.0])])
		AC_DEFINE([CURL_HAS_KEEPALIVE], [1])
	fi
	AC_DEFINE([HAVE_LIBCURL], [1], [Defined to 1 if libcurl support built in])
else
	LIBCURL_LIBS=""
fi
AC_SUBST(LIBCURL_LIBS)


#check execv signature
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
		   #include <process.h>
		   int execv(const char*, const char*const*);
		   ])],
		   AC_DEFINE([EXECV_2ND_ARG_TYPE], [const char* const*], [int execv(const char*, const char*const*);]),
		   AC_DEFINE([EXECV_2ND_ARG_TYPE], [char* const*], [int execv(const char*, char*const*);]))

dnl CCAN wants to know a lot of vars.
# All the configuration checks.  Regrettably, the __attribute__ checks will
# give false positives on old GCCs, since they just cause warnings.  But that's
# fairly harmless.
AC_COMPILE_IFELSE([AC_LANG_SOURCE([static void __attribute__((cold)) cleanup(void) { }])],
			  AC_DEFINE([HAVE_ATTRIBUTE_COLD], [1],
                                    [Define if __attribute__((cold))]))
AC_COMPILE_IFELSE([AC_LANG_SOURCE([static void __attribute__((const)) cleanup(void) { }])],
			  AC_DEFINE([HAVE_ATTRIBUTE_CONST], [1],
                                    [Define if __attribute__((const))]))
AC_COMPILE_IFELSE([AC_LANG_SOURCE([static void __attribute__((noreturn)) cleanup(void) { exit(1); }])],
			  AC_DEFINE([HAVE_ATTRIBUTE_NORETURN], [1],
                                    [Define if __attribute__((noreturn))]))
AC_COMPILE_IFELSE([AC_LANG_SOURCE([static void __attribute__((format(__printf__, 1, 2))) cleanup(const char *fmt, ...) { }])],
			  AC_DEFINE([HAVE_ATTRIBUTE_PRINTF], [1],
                                    [Define if __attribute__((format(__printf__)))]))
AC_COMPILE_IFELSE([AC_LANG_SOURCE([static void __attribute__((unused)) cleanup(void) { }])],
			  AC_DEFINE([HAVE_ATTRIBUTE_UNUSED], [1],
                                    [Define if __attribute__((unused))]))
AC_COMPILE_IFELSE([AC_LANG_SOURCE([static void __attribute__((used)) cleanup(void) { }])],
			  AC_DEFINE([HAVE_ATTRIBUTE_USED], [1],
                                    [Define if __attribute__((used))]))
AC_LINK_IFELSE([AC_LANG_SOURCE([int main(void) { return __builtin_constant_p(1) ? 0 : 1; }])],
			  AC_DEFINE([HAVE_BUILTIN_CONSTANT_P], [1],
                                    [Define if have __builtin_constant_p]))
AC_LINK_IFELSE([AC_LANG_SOURCE([int main(void) { return __builtin_types_compatible_p(char *, int) ? 1 : 0; }])],
			  AC_DEFINE([HAVE_BUILTIN_TYPES_COMPATIBLE_P], [1],
                                    [Define if have __builtin_types_compatible_p]))
AC_COMPILE_IFELSE([AC_LANG_SOURCE([static int __attribute__((warn_unused_result)) func(int x) { return x; }])],
			  AC_DEFINE([HAVE_WARN_UNUSED_RESULT], [1],
                                    [Define if __attribute__((warn_unused_result))]))

if test "x$prefix" = xNONE; then
	prefix=/usr/local
fi

AC_DEFINE_UNQUOTED([CGMINER_PREFIX], ["$prefix/bin"], [Path to cgminer install])

AC_SUBST(JANSSON_LIBS)
AC_SUBST(PTHREAD_FLAGS)
AC_SUBST(DLOPEN_FLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(NCURSES_LIBS)
AC_SUBST(PDCURSES_LIBS)
AC_SUBST(WS2_LIBS)
AC_SUBST(MM_LIBS)
AC_SUBST(MATH_LIBS)
AC_SUBST(RT_LIBS)

AC_CONFIG_FILES([
	Makefile
	compat/Makefile
	ccan/Makefile
	lib/Makefile
	])
AC_OUTPUT


echo
echo
echo
echo "------------------------------------------------------------------------"
echo "$PACKAGE $VERSION"
echo "------------------------------------------------------------------------"
echo
echo
echo "Configuration Options Summary:"
echo

if test "x$libcurl" != xno; then
	echo "  libcurl(GBT+getwork).: Enabled: $LIBCURL_LIBS"
else
	echo "  libcurl(GBT+getwork).: Disabled"
fi

echo "  curses.TUI...........: $cursesmsg"


echo

if test "x$bitmain" = xyes; then
	echo "  Bitmain.MultiChain...: Enabled"
else
	echo "  Bitmain.MultiChain...: Disabled"
fi

if test "x$bitmain_c5" = xyes; then
	echo "  Bitmain.C5...: Enabled"
else
	echo "  Bitmain.C5...: Disabled"
fi

#Add any new device to this, along with a no on the end of the test
if test "x$bitmain$bitmain_c5" = xnono; then
	echo
	AC_MSG_ERROR([No mining devices configured in])
	echo
fi

if test "x$standalone" = xyes; then
	if test $drivercount != x; then
		echo
		AC_MSG_ERROR([You have configured more than one driver in with a driver that is designed to be standalone only (see ./configure --help)])
		echo
	fi
fi

echo
echo "Compilation............: make (or gmake)"
echo "  CPPFLAGS.............: $CPPFLAGS"
echo "  CFLAGS...............: $CFLAGS"
echo "  LDFLAGS..............: $LDFLAGS $PTHREAD_FLAGS"
echo "  LDADD................: $DLOPEN_FLAGS $LIBCURL_LIBS $JANSSON_LIBS $PTHREAD_LIBS $NCURSES_LIBS $PDCURSES_LIBS $WS2_LIBS $MATH_LIBS $LIBUSB_LIBS $RT_LIBS"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo
if test "x$want_usbutils$dlibusb" = xyesyes; then
echo "*** SYSTEM LIBUSB BEING ADDED - NOT RECOMMENDED UNLESS YOU ARE UNABLE TO COMPILE THE INCLUDED LIBUSB ***"
echo
fi
