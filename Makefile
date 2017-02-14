VERSION=$(shell git log -1|grep commit|cut -f 2 -d ' '|head -c 7)
DIR?=/usr/share/crypto-policies
BINDIR?=/usr/bin
MANDIR?=/usr/share/man/man8
DESTDIR?=

all: update-crypto-policies.8

install: update-crypto-policies.8
	mkdir -p $(DESTDIR)/$(MANDIR)
	mkdir -p $(DESTDIR)/$(BINDIR)
	install -p -m 644 update-crypto-policies.8 $(DESTDIR)/$(MANDIR)
	install -p -m 755 update-crypto-policies $(DESTDIR)/$(BINDIR)
	mkdir -p $(DESTDIR)/$(DIR)/
	install -p -m 644 default-config $(DESTDIR)/$(DIR)
	./generate-policies.pl $(DESTDIR)/$(DIR)

check:
	@-rm -f test-suite.log
	tests/openssl.pl >test-suite.log
	tests/gnutls.pl >>test-suite.log
	tests/java.pl >>test-suite.log
	tests/verify-output.pl >>test-suite.log

reset-outputs:
	@rm -rf tests/outputs
	echo "Outputs were reset. Run make check to re-generate, and commit the output."

clean:
	rm -f update-crypto-policies.8 update-crypto-policies.8.xml

update-crypto-policies.8: update-crypto-policies.8.txt
	asciidoc.py -v -d manpage -b docbook update-crypto-policies.8.txt
	xsltproc --nonet -o update-crypto-policies.8 /usr/share/asciidoc/docbook-xsl/manpage.xsl update-crypto-policies.8.xml

dist:
	rm -rf crypto-policies && git clone . crypto-policies && rm -rf crypto-policies/.git/ && tar -czf crypto-policies-git$(VERSION).tar.gz crypto-policies && rm -rf crypto-policies
