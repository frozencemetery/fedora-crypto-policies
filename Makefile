VERSION=$(shell git log -1|grep commit|cut -f 2 -d ' '|head -c 7)
DIR?=/usr/share/crypto-policies
BINDIR?=/usr/bin
MANDIR?=/usr/share/man
DESTDIR?=
MAN7PAGES=crypto-policies.7
MAN8PAGES=update-crypto-policies.8 fips-finish-install.8 fips-mode-setup.8
SCRIPTS=update-crypto-policies fips-finish-install fips-mode-setup

all: $(MAN7PAGES) $(MAN8PAGES)

install: $(MANPAGES)
	mkdir -p $(DESTDIR)/$(MANDIR)
	mkdir -p $(DESTDIR)/$(MANDIR)/man7
	mkdir -p $(DESTDIR)/$(MANDIR)/man8
	mkdir -p $(DESTDIR)/$(BINDIR)
	install -p -m 644 $(MAN7PAGES) $(DESTDIR)/$(MANDIR)/man7
	install -p -m 644 $(MAN8PAGES) $(DESTDIR)/$(MANDIR)/man8
	install -p -m 755 $(SCRIPTS) $(DESTDIR)/$(BINDIR)
	mkdir -p $(DESTDIR)/$(DIR)/
	install -p -m 644 default-config $(DESTDIR)/$(DIR)
	./generate-policies.pl $(DESTDIR)/$(DIR)

check:
	@-rm -f test-suite.log
	tests/verify-output.pl 2>>test-suite.log
	tests/openssl.pl 2>>test-suite.log
	tests/gnutls.pl 2>>test-suite.log
	tests/nss.pl 2>>test-suite.log
	tests/java.pl 2>>test-suite.log
	tests/krb5.py 2>>test-suite.log
	top_srcdir=. tests/update-crypto-policies.sh | tee -a test-suite.log

reset-outputs:
	@rm -rf tests/outputs/*
	echo "Outputs were reset. Run make check to re-generate, and commit the output."

clean:
	rm -f $(MAN7PAGES) $(MAN8PAGES) *.?.xml

%: %.txt
	asciidoc.py -v -d manpage -b docbook $<
	xsltproc --nonet -o $@ /usr/share/asciidoc/docbook-xsl/manpage.xsl $@.xml

dist:
	rm -rf crypto-policies && git clone . crypto-policies && rm -rf crypto-policies/.git/ && tar -czf crypto-policies-git$(VERSION).tar.gz crypto-policies && rm -rf crypto-policies
