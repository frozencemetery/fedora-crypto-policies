# A reasonable default for today's standards. It should provide
# 112-bit security with the exception of SHA1 signatures needed for DNSSec
# and other still prevalent legacy use of SHA1 signatures.

# MACs: all HMAC with SHA1 or better + all modern MACs (Poly1305 etc)
# Curves: all prime >= 255 bits (including Bernstein curves)
# Signature algorithms: with SHA-1 hash or better (no DSA)
# TLS Ciphers: >= 128-bit key, >= 128-bit block (AES, ChaCha20, including AES-CBC)
# non-TLS Ciphers: as TLS Ciphers with added Camellia
# key exchange: ECDHE, RSA, DHE (no DHE-DSS)
# DH params size: >= 1023
# RSA params size: >= 2048
# TLS protocols: TLS >= 1.0

sub update_lists {

    @mac_list = ('AEAD', 'HMAC-SHA2-256', 'HMAC-SHA1', 'UMAC-128', 'HMAC-SHA2-384', 'HMAC-SHA2-512');
    @group_list = ('X25519', 'X448', 'SECP256R1', 'SECP384R1', 'SECP521R1',
        'FFDHE-2048', 'FFDHE-3072', 'FFDHE-4096', 'FFDHE-6144', 'FFDHE-8192');
    @hash_list = ('SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHA2-224', 'SHA1');
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

    @tls_cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'CHACHA20-POLY1305', 'AES-256-CBC',
        'AES-128-GCM', 'AES-128-CCM', 'AES-128-CBC');
    @cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'CHACHA20-POLY1305', 'CAMELLIA-256-GCM',
        'AES-256-CTR', 'AES-256-CBC', 'CAMELLIA-256-CBC', 
        'AES-128-GCM', 'AES-128-CCM', 'CAMELLIA-128-GCM', 'AES-128-CTR', 'AES-128-CBC', 'CAMELLIA-128-CBC');

# 'RSA' is intentionally before DHE ciphersuites, as the DHE ciphersuites have
# interoperability issues in TLS.
    @key_exchange_list = ('ECDHE', 'RSA', 'DHE', 'DHE-RSA', 'PSK', 'DHE-PSK', 'ECDHE-PSK');

    @protocol_list = ('TLS1.3', 'TLS1.2', 'TLS1.1', 'TLS1.0', 'DTLS1.2', 'DTLS1.0');
    @ike_protocol_list = ('IKEv2');

    $min_tls_version = 'TLS1.0';
    $min_dtls_version = 'DTLS1.0';

    # Parameter sizes
    $min_dh_size = 1023;
    $min_dsa_size = 2048;
    $min_rsa_size = 2048;
    # GnuTLS only for now
    $sha1_in_certs = 1;

    update_rev_lists();
}

update_lists();
