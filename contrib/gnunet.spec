#
# rpm spec file for package GNUnet (Version 0.6.3)
#
# (C) 2001, 2002, 2003, 2004 SSS Lab, CS, Purdue
#
# Please send bugfixes or comments to 
# gnunet-developers@mail.gnu.org

Vendor:       Secure Software Systems Lab, CS Dept., Purdue University
Distribution: Drongo (i386) 
Name:         GNUnet
Release:      0 
Packager:     christian@grothoff.org
License:      GPL
Group:        Network/Security
Provides:     gnunet
Requires:     gtk+ >= 1.2, libextractor >= 0.3.3
Summary:      Framework for Secure Peer-to-Peer networking
URL:          http://www.gnu.org/software/GNUnet/
Version:      0.6.3
Source:       http://www.ovmj.org/GNUnet/download/GNUnet-%{version}.tar.gz
BuildRoot:    %{_tmppath}/%{name}-%{version}-%{release}-root
# Note that you can only build this RPM if the current GNUnet version
# is already installed in /usr. The reason is, that a GNUnet library
# (afsprotocol) is linked against another couple of libraries which
# are NOT found in BuildRoot in the "make install" stage when for some
# odd reason libtool decides to re-link the library :-(. I've spend 6h
# on this one, there does not seem to be a clean solution.  Note that
# without the RPM script foo around it, the build works just fine.

%description
GNUnet is framework for secure peer-to-peer networking.  The primary
application for GNUnet is anonymous file-sharing.  GNUnet is part of
the GNU project (http://www.gnu.org/).

While GNUnet file-sharing provides anonymity for its users, it also
provides accounting to perform better resource allocation.
Contributing users are rewarded with better service.  Peers monitor the
behavior of other peers and allocate resources for peers that are
economically trusted.  The content encoding makes it hard for peers to
circumvent the reward system. 

GNUnet supports multiple transport protocols, currently UDP, TCP, HTTP
and SMTP.  The framework automatically chooses a cheap transport that
is currently available by both peers for any given link.  It is
possible to run GNUnet peers behind NAT boxes and almost all firewall
configurations.

This is a beta version.  The important features have been implemented
and tested.  The security features are in place, but note that
anonymity may be limited due to the small number of active
participants.

For a more detailed description of GNUnet, see our webpages at:

http://www.gnu.org/software/GNUnet/ and
http://www.ovmj.org/GNUnet/

Note that this RPM does not include the database frontends for tdb and
mysql (only gdbm, bdb and plain directories are included).



Authors:
--------
    Blake Matheny <bmatheny@purdue.edu>
    Christian Grothoff <christian@grothoff.org>
    Glenn McGrath <bug1@iinet.net.au>
    Igor Wronsky <iwronsky@users.sourceforge.net>
    Krista Bennett <krista@grothoff.org>
    Nils Durner <N.Durner@t-online.de>

%prep
rm -rf $RPM_BUILD_ROOT
%setup -q -n GNUnet-%{version}

%build
%configure
make

%install
%makeinstall

rm -f $RPM_BUILD_ROOT/usr/lib/*.a
rm -f $RPM_BUILD_ROOT/usr/lib/*_tdb.*
rm -f $RPM_BUILD_ROOT/usr/lib/*_mysql.*
rm -f $RPM_BUILD_ROOT/usr/lib/*.a
rm -f $RPM_BUILD_ROOT/usr/lib/libgnunettestbed_protocol*
rm -f $RPM_BUILD_ROOT/usr/lib/libgnunetrpc*
rm -f $RPM_BUILD_ROOT/usr/lib/libgnunetdht*
mkdir -p $RPM_BUILD_ROOT/etc
cp contrib/gnunet.root $RPM_BUILD_ROOT/etc/gnunet.conf
mkdir -p $RPM_BUILD_ROOT/etc/skel/.gnunet/
cp contrib/gnunet.user $RPM_BUILD_ROOT/etc/skel/.gnunet/gnunet.conf
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
cp contrib/initgnunet $RPM_BUILD_ROOT/etc/rc.d/init.d/gnunetd

%post
groupadd -r -f gnunet &>/dev/null || groupadd -f gnunet &> /dev/null || true
mkdir -p /var/lib/GNUnet
useradd -r -g gnunet -d /var/lib/GNUnet gnunet &>/dev/null || useradd -g gnunet -d /var/lib/GNUnet gnunet &> /dev/null || true
chmod 775 /var/lib/GNUnet
chown -R gnunet:gnunet /var/lib/GNUnet &> /dev/null
echo " "
echo " "
echo "Configure gnunetd by editing"
echo "# vi /etc/gnunet.conf"
echo "Start gnunetd as root with"
echo "# /etc/rc.d/init.d/gnunetd start"
echo "Test that gnunetd operates properly with"
echo "$ gnunet-stats"
echo "Diagnose errors reading the log-file in"
echo "$ tail -f /var/lib/GNUnet/logs"
echo "A default user configuration was installed"
echo "under /etc/skel/.gnunet/gnunet.conf"
echo "This is NOT the same configuration as the one for gnunetd!"
/sbin/ldconfig

%files
%defattr(- root, root)
%{_bindir}/gnunet-chat
%{_bindir}/gnunet-check
%{_bindir}/gnunet-convert
%{_bindir}/gnunet-delete
%{_bindir}/gnunet-directory-emptydb
%{_bindir}/gnunet-directory-listdb
%{_bindir}/gnunet-directory-print
%{_bindir}/gnunet-download
%{_bindir}/gnunet-gtk
%{_bindir}/gnunet-insert
%{_bindir}/gnunet-peer-info
%{_bindir}/gnunet-pseudonym-create
%{_bindir}/gnunet-pseudonym-delete
%{_bindir}/gnunet-pseudonym-list
%{_bindir}/gnunet-search
%{_bindir}/gnunet-search-sblock
%{_bindir}/gnunet-setup
%{_bindir}/gnunet-stats
%{_bindir}/gnunet-tbench
%{_bindir}/gnunet-testbed
%{_bindir}/gnunet-tracekit
%{_bindir}/gnunet-transport-check
%{_bindir}/gnunet-update
%{_bindir}/gnunetd
%{_libdir}/libgnunet_afs_esed2.la
%{_libdir}/libgnunet_afs_esed2.so
%{_libdir}/libgnunet_afs_esed2.so.0
%{_libdir}/libgnunet_afs_esed2.so.0.0.0
%{_libdir}/libgnunetafs_database_bdb.la
%{_libdir}/libgnunetafs_database_bdb.so
%{_libdir}/libgnunetafs_database_gdbm.la
%{_libdir}/libgnunetafs_database_gdbm.so
#%{_libdir}/libgnunetafs_database_tdb.la
#%{_libdir}/libgnunetafs_database_tdb.so
#%{_libdir}/libgnunetafs_database_mysql.la
#%{_libdir}/libgnunetafs_database_mysql.so
%{_libdir}/libgnunetafs_database_directory.la
%{_libdir}/libgnunetafs_database_directory.so
%{_libdir}/libgnunetafs_protocol.la
%{_libdir}/libgnunetafs_protocol.so
#%{_libdir}/libgnunettestbed_protocol.la
#%{_libdir}/libgnunettestbed_protocol.so
%{_libdir}/libgnunettracekit_protocol.la
%{_libdir}/libgnunettracekit_protocol.so
%{_libdir}/libgnunetchat_protocol.la
%{_libdir}/libgnunetchat_protocol.so
%{_libdir}/libgnunettbench_protocol.la
%{_libdir}/libgnunettbench_protocol.so
%{_libdir}/libgnunettransport_http.la
%{_libdir}/libgnunettransport_http.so
%{_libdir}/libgnunettransport_nat.la
%{_libdir}/libgnunettransport_nat.so
%{_libdir}/libgnunettransport_smtp.la
%{_libdir}/libgnunettransport_smtp.so
%{_libdir}/libgnunettransport_tcp.la
%{_libdir}/libgnunettransport_tcp.so
%{_libdir}/libgnunettransport_udp.la
%{_libdir}/libgnunettransport_udp.so
%{_libdir}/libgnunetutil.la
%{_libdir}/libgnunetutil.so
%{_libdir}/libgnunetutil.so.0
%{_libdir}/libgnunetutil.so.0.0.0
%{_prefix}/../etc/gnunet.conf
%{_prefix}/../etc/skel/.gnunet/gnunet.conf
%{_prefix}/../etc/rc.d/init.d/gnunetd
%doc %{_mandir}/man1/gnunet-chat.1.gz
%doc %{_mandir}/man1/gnunet-check.1.gz
%doc %{_mandir}/man1/gnunet-convert.1.gz
%doc %{_mandir}/man1/gnunet-delete.1.gz
%doc %{_mandir}/man1/gnunet-directory-emptydb.1.gz
%doc %{_mandir}/man1/gnunet-directory-listdb.1.gz
%doc %{_mandir}/man1/gnunet-directory-print.1.gz
%doc %{_mandir}/man1/gnunet-download.1.gz
%doc %{_mandir}/man1/gnunet-gtk.1.gz
%doc %{_mandir}/man1/gnunet-insert.1.gz
%doc %{_mandir}/man1/gnunet-peer-info.1.gz
%doc %{_mandir}/man1/gnunet-pseudonym-create.1.gz
%doc %{_mandir}/man1/gnunet-pseudonym-delete.1.gz
%doc %{_mandir}/man1/gnunet-pseudonym-list.1.gz
%doc %{_mandir}/man1/gnunet-search.1.gz
%doc %{_mandir}/man1/gnunet-search-sblock.1.gz
%doc %{_mandir}/man1/gnunet-stats.1.gz
%doc %{_mandir}/man1/gnunet-tbench.1.gz
%doc %{_mandir}/man1/gnunet-testbed.1.gz
%doc %{_mandir}/man1/gnunet-tracekit.1.gz
%doc %{_mandir}/man1/gnunet-transport-check.1.gz
%doc %{_mandir}/man1/gnunet-update.1.gz
%doc %{_mandir}/man1/gnunetd.1.gz 
%doc %{_mandir}/man5/gnunet.conf.5.gz

%changelog 
* Mon Aug  2 2004 Christian Grothoff <christian@grothoff.org>
- incomplete updates towards making it work with 0.6.3

* Wed Dec 31 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- bumping version to 0.6.1
- updated description and author list

* Tue Dec 23 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- bumping version to 0.6.1
- added gnunet-setup binary

* Mon Dec  8 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- replaced manpage gnunet-directory with the more specific
  gnunet-directory-{emptydb|listdb|print} pages.  Also
  added gnunet-testbed manpage.

* Mon Sep 29 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- adding testbed module (NOT included in binary RPM since it is 
  pre-alpha)
- bumping version to 0.6.0

* Wed Aug 20 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- minor adjustments for 0.5.5

* Thu Jun 26 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- bumping version to GNUnet 0.5.4a

* Sat May 17 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- bumping version to GNUnet 0.5.4
- also remove mysql files from build directory if they were
  build by chance

* Tue Apr 29 2003 Per Kreuger <piak@sics.se>
- delete files in build directory that are not to be installed
  as required by rpm 4.2
- add missing files to install list
- updated version

* Sat Apr  5 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- adding gnunet-delete

* Mon Mar 17 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- releasing GNUnet 0.5.2a
- cleaning up RPM 

* Thu Feb 27 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- releasing GNUnet 0.5.2

* Thu Feb 20 2003 Chrsitian Grothoff <grothoff@cs.purdue.edu>
- added gnunet-tracekit

* Thu Feb  6 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- added missing dynamic library (afspolicy)

* Tue Feb  4 2003 Christian Grothoff <grothoff@cs.purdue.edu>
- Releasing GNUnet 0.5.1

* Sat Dec 21 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- releasing GNUnet 0.5.0

* Wed Nov 27 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- added gnunet-tbench tool

* Wed Nov 20 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- added gnunet-transport-check tool

* Wed Nov 06 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- updated list of dynamic libraries

* Mon Sep 16 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- bumped version number to 0.4.9
- added gnunet-chat program and man-page
- added dynamic libraries

* Fri Aug 16 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- bumped version number to 0.4.5

* Wed Jul 31 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- bumped version number to 0.4.4
- moved installation directory to /usr
- gnunet-insert no longer SGID (no longer needed)

* Fri Jul 26 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- now depends on libextractor 0.1.1

* Fri Jul 19 2002 Christian Grothoff <grothoff@cs.purdue.edu> 
- improved description
- bumped version number to 0.4.3

* Mon Jul 15 2002 Christian Grothoff <grothoff@cs.purdue.edu> 
- added gnunet-check (binary and man-page)

* Thu Jul 11 2002 Marko Kolar <marko.kolar@guest.arnes.si>
- fixed dependency line (need spaces around version requirements)
- added defattr to force root:root even if rpm not build by root

* Sun Jun 16 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- added gnunet-stats

* Wed Jun  5 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- stop downloading the hostlist in the postinstall, gnunetd
  can do that now on startup 

* Thu May 30 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- new server is ovmj.org, no longer gecko
- bumped version to 0.4.0
- moved FHS conform from /var/GNUnet to /var/lib/GNUnet

* Fri Apr  5 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- added man-pages to the RPM

* Sun Mar 31 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- bumped version to 0.3.3 (not released yet)
- added gnunet-gtk to the rpm (works!)
- made gtk dependency precise (1.2 or higher, 2.x should also do)

* Sun Mar 17 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- bumped version to 0.3.2
- put configuration in ~/.gnunet/gnunet.conf
- added requirement for gtk+

* Sat Mar  2 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- bumped version to 0.3.1
- added new console tools
- removed gtk+ dependency (no GUI included at the moment)

* Sat Feb 16 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- changing name to GNUnet
- removed gproxy (not based on free software)

* Sun Feb  3 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- removed dependency on zlib (no longer required)

* Sat Feb  2 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- added mp32gnunet binary 

* Mon Jan 21 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- updated version number to 0.3.0
- updated comments to reflect the status of the project 

* Sun Jan 20 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- made insertfile sgid to allow writing to /var/gnunet
- made /var/gnunet group writeable
- renamed gnunet to gnunetd, insertfile to gnunetinsert
  updatehosts to gnunetupdate
- bumped version to 0.2.2-3

* Wed Jan 16 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- renamed startscript to "gnunetd"
- added automatic download of initial hostlist to post-install
- now able to build directly to $RPM_BUILD_DIR
- made RH specific -r flag in useradd/groupadd "optional"

* Sun Jan 13 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- bumped version to 0.2.2
- added startscript /etc/rc.d/init.d/gnunet
- made sure user and group gnunet get created

* Fri Jan  4 2002 Christian Grothoff <grothoff@cs.purdue.edu>
- Added prefix to allow adjustment of the location of the binaries
- bumped version to 0.2.1
- used "*" for library versions instead of fixed version number
- added script to obtain hostlist from gecko

