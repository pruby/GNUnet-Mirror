if HAVE_GUILE
 bin_SCRIPTS = gnunet-download-manager.scm
endif

pkgdata_DATA = \
 config-client.in \
 config-daemon.in

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) gnunet-logo-color.png $(DESTDIR)$(pkgdatadir)
	@$(NORMAL_INSTALL)

EXTRA_DIST = \
 gnunet-logo-color.png \
 hostlist.cgi \
 hostlist.php \
 gnunet-download-manager.scm \
 init_gnunet_redhat init_gnunet_ubuntu \
 visualize_stats.sh \
 gnmessage.sh \
 junkinsert.sh \
 junklookup.sh \
 namespacehelper.sh \
 report.sh \
 $(pkgdata_DATA)
