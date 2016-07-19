VERSION=$(shell git log -1|grep commit|cut -f 2 -d ' '|head -c 7)
DIR?=/usr/libexec/crypto-policies
BINDIR?=/usr/bin
MANDIR?=/usr/share/man/man8
DESTDIR?=

all: update-crypto-policies.8

install: update-crypto-policies.8
	install -p -m 644 update-crypto-policies.8 $(DESTDIR)/$(MANDIR)
	install -p -m 755 update-crypto-policies $(DESTDIR)/$(BINDIR)
	mkdir -p $(DESTDIR)/$(DIR)/profiles
	for i in back-ends/*pl;do install -p -m 755 $$i $(DESTDIR)/$(DIR);done
	for i in back-ends/profiles/*;do install -p -m 755 $$i $(DESTDIR)/$(DIR)/profiles;done
	sed -i 's|/usr/libexec/crypto-policies|'"$(DIR)"'|g' $(DESTDIR)/$(BINDIR)/update-crypto-policies

check:
	@-rm -f test-suite.log
	tests/openssl.pl >test-suite.log
	tests/gnutls.pl >>test-suite.log
	tests/java.pl >>test-suite.log
	tests/verify-output.pl >>test-suite.log

clean:
	rm -f update-crypto-policies.8 update-crypto-policies.8.xml

update-crypto-policies.8: update-crypto-policies.8.txt
	asciidoc.py -v -d manpage -b docbook update-crypto-policies.8.txt
	xsltproc --nonet -o update-crypto-policies.8 /usr/share/asciidoc/docbook-xsl/manpage.xsl update-crypto-policies.8.xml

dist:
	rm -rf crypto-policies && git clone . crypto-policies && rm -rf crypto-policies/.git/ && tar -czf crypto-policies-git$(VERSION).tar.gz crypto-policies && rm -rf crypto-policies
