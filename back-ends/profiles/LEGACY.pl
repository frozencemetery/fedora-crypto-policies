# A level that will ensure maximum compatibility with legacy systems.
# It should provide at least 64-bit security and include RC4 and MD5 (for HMAC).

# MACs: MD5, SHA1+
# Curves: All supported
# Signature algorithms: must use SHA-1 hash or better
# (Note: signature algorithms restrictions shouldn't apply to self-signatures)
# Ciphers: AES-GCM, AES-CCM, AES-CBC, CAMELLIA-GCM, CAMELLIA-CBC, 3DES-CBC, RC4
# Key exchange: ECDHE, RSA, DHE
# DH params size: 767+
# RSA params size: 767+
# Protocols: All supported (SSL3.0+)

sub update_lists {

    @mac_list = @full_mac_list;
    @curve_list = @full_curve_list;
    @hash_list = @full_hash_list;
    @sign_list = ('RSA-SHA1', 'DSA-SHA1', 'ECDSA-SHA1',
        'RSA-SHA2-224', 'DSA-SHA2-224', 'ECDSA-SHA2-224',
        'RSA-SHA2-256', 'DSA-SHA2-256', 'ECDSA-SHA2-256',
        'RSA-SHA2-384', 'DSA-SHA2-384', 'ECDSA-SHA2-384',
        'RSA-SHA2-512', 'DSA-SHA2-512', 'ECDSA-SHA2-512',
        'RSA-SHA3-256', 'DSA-SHA3-256', 'ECDSA-SHA3-256',
        'RSA-SHA3-384', 'DSA-SHA3-384', 'ECDSA-SHA3-384',
        'RSA-SHA3-512', 'DSA-SHA3-512', 'ECDSA-SHA3-512');

    @cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'CHACHA20-POLY1305', 'CAMELLIA-256-GCM',
        'AES-256-CBC', 'CAMELLIA-256-CBC', 
        'AES-128-GCM', 'AES-128-CCM', 'CAMELLIA-128-GCM', 'AES-128-CBC', 'CAMELLIA-128-CBC',
        '3DES-CBC', 'RC4-128');
    @key_exchange_list = ('ECDHE', 'RSA', 'DHE', 'PSK', 'DHE-PSK', 'ECDHE-PSK');
    @protocol_list = ('TLS1.2', 'TLS1.1', 'TLS1.0', 'SSL3.0', 'DTLS1.2', 'DTLS1.0');

    $min_tls_version = 'SSL3.0';
    $min_dtls_version = 'SSL3.0';

    # Parameter sizes
    $min_dh_size = 767;
    $min_dsa_size = 767;
    $min_rsa_size = 767;

    update_rev_lists();
}

update_lists();
