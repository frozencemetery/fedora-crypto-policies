VERSION=$(shell git log -1|grep commit|cut -f 2 -d ' '|head -c 7)

all: update-crypto-policies.8

install: update-crypto-policies.8
	install -p -m 644 update-crypto-policies.8 /usr/share/man/man8
	install -p -m 755 update-crypto-policies /usr/bin
	mkdir -p /usr/share/crypto-policies/profiles
	for i in profiles/*;do install -p -m 755 $$i /usr/share/crypto-policies/profiles;done

check:
	@-rm -f test-suite.log
	tests/openssl.sh >test-suite.log
	tests/gnutls.sh >>test-suite.log
	tests/java.sh >>test-suite.log

clean:
	rm -f update-crypto-policies.8 update-crypto-policies.8.xml

update-crypto-policies.8: update-crypto-policies.8.txt
	asciidoc.py -v -d manpage -b docbook update-crypto-policies.8.txt
	xsltproc --nonet -o update-crypto-policies.8 /usr/share/asciidoc/docbook-xsl/manpage.xsl update-crypto-policies.8.xml

dist:
	rm -rf crypto-policies && git clone . crypto-policies && rm -rf crypto-policies/.git/ && tar -czf crypto-policies-git${VERSION}.tar.gz crypto-policies
