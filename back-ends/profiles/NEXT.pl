# A reasonable default for today's standards. For Fedora it should provide
# 112-bit security with the exception of SHA1 signatures needed for DNSSec
# and other still prevalent legacy use of SHA1 signatures.

# MACs: All HMAC with SHA1 or better + all modern MACs (poly1305 etc)
# Curves: all prime >= 255 bits (including bernstein curves)
# Signature algorithms: with SHA-1 hash or better (not DSA)
# TLS Ciphers: >= 128-bit key, >= 128-bit block (aes, camellia, chacha20, including aes-cbc)
# non-TLS Ciphers: same
# key exchange: ECDHE, RSA, DHE (not DHE-DSS)
# DH params size: >= 2048
# RSA params size: >= 2048
# TLS protocols: TLS >= 1.2, DTLS >= 1.2

sub update_lists {

    @mac_list = ('AEAD', 'HMAC-SHA2-256', 'HMAC-SHA1', 'UMAC-128', 'HMAC-SHA2-384', 'HMAC-SHA2-512');
    @group_list = ('X25519', 'X448', 'SECP256R1', 'SECP384R1', 'SECP521R1',
        'FFDHE-2048', 'FFDHE-3072', 'FFDHE-4096', 'FFDHE-6144', 'FFDHE-8192');
    @hash_list = ('SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHA1');
    @sign_list = (
        'RSA-SHA2-256', 'ECDSA-SHA2-256',
        'RSA-SHA2-384', 'ECDSA-SHA2-384',
        'RSA-SHA2-512', 'ECDSA-SHA2-512',
        'RSA-SHA3-256', 'ECDSA-SHA3-256',
        'RSA-SHA3-384', 'ECDSA-SHA3-384',
        'RSA-SHA3-512', 'ECDSA-SHA3-512',
        'EDDSA-ED25519', 'EDDSA-ED448',
        'RSA-PSS-SHA2-256', 'RSA-PSS-SHA2-384', 'RSA-PSS-SHA2-512',
        'RSA-SHA2-224', 'ECDSA-SHA2-224',
        'RSA-PSS-SHA1', 'RSA-SHA1', 'ECDSA-SHA1');

    @tls_cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'CHACHA20-POLY1305', 'CAMELLIA-256-GCM',
        'AES-256-CTR', 'AES-256-CBC', 'CAMELLIA-256-CBC', 
        'AES-128-GCM', 'AES-128-CCM', 'CAMELLIA-128-GCM', 'AES-128-CTR', 'AES-128-CBC', 'CAMELLIA-128-CBC');
    @cipher_list = @tls_cipher_list;

# 'RSA' is intentionally before DHE ciphersuites, as the DHE ciphersuites have
# interoperability issues in TLS.
    @key_exchange_list = ('ECDHE', 'RSA', 'DHE', 'DHE-RSA', 'PSK', 'DHE-PSK', 'ECDHE-PSK');
#    @protocol_list = ('TLS1.2', 'DTLS1.2');
#    $min_tls_version = 'TLS1.2';
#    $min_dtls_version = 'DTLS1.2';

    @protocol_list = ('TLS1.3', 'TLS1.2', 'DTLS1.2');
    @ike_protocol_list = ('IKEv2');

    $min_tls_version = 'TLS1.2';
    $min_dtls_version = 'DTLS1.2';

    # Parameter sizes
    $min_dh_size = 2048;
    $min_dsa_size = 2048;
    $min_rsa_size = 2048;
    # NSS only for now
    $sha1_in_certs = 0;

    update_rev_lists();
}

update_lists();
