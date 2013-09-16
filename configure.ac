AC_PREREQ(2.59)
AC_INIT(netsukuku, 0.0.9b)
AM_INIT_AUTOMAKE(netsukuku, 0.0.9b)
AC_DEFINE(VERSION, 0.0.9b)
AM_CONFIG_HEADER(src/config.h) 

dnl -----------------------------------
dnl Get hostname and other information.
dnl -----------------------------------
AC_CANONICAL_HOST

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX

prefix=/usr
datadir=/usr/share/netsukuku
sysconfdir=/etc/netsukuku
piddir=/var/run

AC_ARG_WITH(gmp-include, AS_HELP_STRING([--with-gmp-include], \
[gmp include dir]), [gmp="$withval"])
AC_SUBST(gmp)


AC_HEADER_STDC
AC_CHECK_HEADERS([unistd.h])

AC_CHECK_HEADERS([pthread.h], ,\
        [echo "============================ Unable to find pthread.h"; \
         echo "Do you have the libpthread library installed?" ])
AC_CHECK_HEADERS([zlib.h], ,\
        [echo "============================ Unable to find zlib.h"; \
         echo "Do you have the zlib library installed?" ])
AC_CHECK_HEADERS([openssl/crypto.h], ,\
        [echo "============================ Unable to find openssl/crypto.h";\
         echo "Read README first!!!!!"; \
         echo "Install the openssl library"])
AC_CHECK_HEADERS([gmp.h], ,\
        [echo "============================ Unable to find gmp.h"; \
         echo "Read README first!!!!!"; \
         echo "You need to install the libgmp library."; \
         echo "In the debian the package is libgmp3-dev"])

AC_MSG_CHECKING(OS)
case "$host" in
  *-sunos5.6* | *-solaris2.6*)
      opsys=sol2-6
      AC_DEFINE(SUNOS,,SunOS 5)
      AC_CHECK_LIB(xnet, main)
      AC_MSG_RESULT(solaris)
  ;;
  *-sunos5* | *-solaris2*)
      AC_DEFINE(SUNOS,,SunOS 5)
      AC_CHECK_LIB(socket, main)
      AC_CHECK_LIB(nsl, main)
      AC_MSG_RESULT(solaris)
  ;;
  *-linux-*)
      opsys=gnu-linux
      AC_DEFINE(GNU_LINUX,,GNU Linux)
      AC_MSG_RESULT(linux)
  ;;
  *-nec-sysv4*)
      AC_CHECK_LIB(nsl, gethostbyname)
      AC_CHECK_LIB(socket, socket)
      AC_MSG_RESULT(net-sysv4)
  ;;
  *-freebsd*)
      AC_DEFINE(FREEBSD,,FreeBSD)
      AC_MSG_RESULT(freebsd)
  ;;
  *-openbsd*)
      opsys=openbsd
      AC_DEFINE(OPEN_BSD,,OpenBSD)
      AC_MSG_RESULT(openbsd)
  ;;
  *-bsdi*)
      opsys=bsdi
      OTHER_METHOD="mtu_kvm.o"
      AC_CHECK_LIB(kvm, main)
      AC_MSG_RESULT(bsdi)
  ;;
  *-irix6.5)
      opsys=irix
      AC_DEFINE(IRIX,,IRIX 6.5)
      AC_MSG_RESULT(irix)
  ;;
esac

dnl ------------------------------------
dnl Determine routing get and set method
dnl ------------------------------------
AC_MSG_CHECKING(Netsukuku kernel interface method)
if test x"$opsys" = x"gnu-linux"; then
    AC_MSG_RESULT(netlink)
    RT_METHOD=rt_netlink.o
    AC_DEFINE(HAVE_NETLINK,,netlink)
    netlink=yes
else
  if test "$opsys" = "sol2-6";then
    AC_MSG_RESULT(solaris)
    KERNEL_METHOD="kernel_socket.o"
    RT_METHOD="rt_socket.o"
  elif test "$opsys" = "irix" ; then
    AC_MSG_RESULT(irix)
    KERNEL_METHOD="kernel_socket.o"
    RT_METHOD="rt_socket.o"
  else
    AC_TRY_RUN([#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

main ()
{
  int ac_sock;

  ac_sock = socket (AF_ROUTE, SOCK_RAW, 0);
  if (ac_sock < 0 && errno == EINVAL)
    exit (1);
  exit (0);
}],
  [KERNEL_METHOD=kernel_socket.o
   RT_METHOD=rt_socket.o
   AC_MSG_RESULT(socket)],
  [RT_METHOD=rt_ioctl.o
   AC_MSG_RESULT(ioctl)],
  [KERNEL_METHOD=kernel_socket.o
   RT_METHOD=rt_socket.o
   AC_MSG_RESULT(socket)])
  fi
fi
AC_SUBST(RT_METHOD)
AC_SUBST(KERNEL_METHOD)
AC_SUBST(OTHER_METHOD)


dnl -----------------------------
dnl check interface lookup method
dnl -----------------------------
AC_MSG_CHECKING(interface looking up method)
if test "$netlink" = yes; then
  AC_MSG_RESULT(netlink)
  IF_METHOD=if_netlink.o
else
  if test "$opsys" = "sol2-6";then
    AC_MSG_RESULT(solaris)
    IF_METHOD=if_ioctl.o
  elif test "$opsys" = "irix" ; then
    AC_MSG_RESULT(irix)
     IF_METHOD=if_ioctl.o
  elif test "$opsys" = "openbsd";then
    AC_MSG_RESULT(openbsd)
    IF_METHOD=if_ioctl.o
  elif grep NET_RT_IFLIST /usr/include/sys/socket.h >/dev/null 2>&1; then
    AC_MSG_RESULT(sysctl)
    IF_METHOD=if_sysctl.o
    AC_DEFINE(HAVE_NET_RT_IFLIST,,NET_RT_IFLIST)
  else
    AC_MSG_RESULT(ioctl)
    IF_METHOD=if_ioctl.o
  fi
fi
AC_SUBST(IF_METHOD)



AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug], [Enable Netsukuku debug]),\
[debug_flags="-Wall -DDEBUG"], [debug_flags=""])
AC_SUBST(debug_flags)

AC_DEFINE_UNQUOTED(DATA_DIR, "$datadir", "Where the Netsukuku data is saved")
AC_DEFINE_UNQUOTED(CONF_DIR, "$sysconfdir", "Location of configuration files")
AC_DEFINE_UNQUOTED(PID_DIR, "$piddir", "Location of ntkd.pid file")
AC_ARG_WITH(pid_dir, 
	    [  --with-pid-dir=ARG      Specify location of ntkd.pid file (default /var/run)],\
	    [AC_DEFINE_UNQUOTED(PID_DIR, "$withval", ntkd.pid file location)])
AC_SUBST(CONF_DIR)
AC_SUBST(DATA_DIR)
AC_SUBST(PID_DIR)

AC_CONFIG_FILES([Makefile src/Makefile src/man/Makefile src/scripts/Makefile\
		  src/conf/Makefile src/conf/netsukuku.conf])
AC_OUTPUT
