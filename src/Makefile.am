bin_PROGRAMS = docsis
sysconf_DATA = docsis.def
docsis_SOURCES = docsis.c ethermac.c md5.c docsis_encode.c docsis_decode.c docsis_snmp.c docsis_yy.y docsis_lex.l hmac_md5.c sha1.c parsedef.c

# set the include path found by configure
AM_CPPFLAGS = $(all_includes) $(NETSNMP_CFLAGS) -DSYSCONFDIR=\"$(sysconfdir)\"

# the library search path.
docsis_LDADD = $(all_libraries) $(NETSNMP_LIBS) $(LEXLIB) $(LIBM)
noinst_HEADERS = ethermac.h md5.h docsis.h docsis_common.h docsis_decode.h docsis_encode.h docsis_symtable.h docsis_snmp.h docsis_globals.h sha1.h
EXTRA_DIST=docsis_yy.h
CLEANFILES=docsis_yy.c docsis_yy.h docsis_yy.output docsis_lex.c
DISTCLEANFILES=Makefile
