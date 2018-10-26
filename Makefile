VERSION=$(shell git log -1|grep commit|cut -f 2 -d ' '|head -c 7)
DIR?=/usr/share/crypto-policies
BINDIR?=/usr/bin
MANDIR?=/usr/share/man/man8
DESTDIR?=
MANPAGES=update-crypto-policies.8 fips-finish-install.8 fips-mode-setup.8
SCRIPTS=update-crypto-policies fips-finish-install fips-mode-setup

all: $(MANPAGES)

install: $(MANPAGES)
	mkdir -p $(DESTDIR)/$(MANDIR)
	mkdir -p $(DESTDIR)/$(BINDIR)
	install -p -m 644 $(MANPAGES) $(DESTDIR)/$(MANDIR)
	install -p -m 755 $(SCRIPTS) $(DESTDIR)/$(BINDIR)
	mkdir -p $(DESTDIR)/$(DIR)/
	install -p -m 644 default-config $(DESTDIR)/$(DIR)
	./generate-policies.pl $(DESTDIR)/$(DIR)

check:
	@-rm -f test-suite.log
	tests/verify-output.pl >>test-suite.log
	tests/openssl.pl >test-suite.log
	tests/gnutls.pl >>test-suite.log
	tests/nss.pl >>test-suite.log
	tests/java.pl >>test-suite.log
	tests/krb5.py >>test-suite.log
	top_srcdir=. tests/update-crypto-policies.sh >>test-suite.log

reset-outputs:
	@rm -rf tests/outputs/*
	echo "Outputs were reset. Run make check to re-generate, and commit the output."

clean:
	rm -f $(MANPAGES) *.8.xml

%.8: %.8.txt
	asciidoc.py -v -d manpage -b docbook $<
	xsltproc --nonet -o $@ /usr/share/asciidoc/docbook-xsl/manpage.xsl $@.xml

dist:
	rm -rf crypto-policies && git clone . crypto-policies && rm -rf crypto-policies/.git/ && tar -czf crypto-policies-git$(VERSION).tar.gz crypto-policies && rm -rf crypto-policies
