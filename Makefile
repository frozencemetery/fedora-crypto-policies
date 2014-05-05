all: update-crypto-policies.8

install: update-crypto-policies.8
	install -p -m 644 update-crypto-policies.8 /usr/share/man/man8
	install -p -m 755 update-crypto-policies /usr/bin
	mkdir -p /usr/lib/crypto-policies/profiles
	for i in profiles/*;do install -p -m 755 $$i /usr/lib/crypto-policies/profiles;done

clean:
	rm -f update-crypto-policies.8

update-crypto-policies.8: update-crypto-policies.8.txt
	asciidoc.py -v -d manpage -b docbook update-crypto-policies.8.txt
	xsltproc --nonet -o update-crypto-policies.8 /usr/share/asciidoc/docbook-xsl/manpage.xsl update-crypto-policies.8.xml
