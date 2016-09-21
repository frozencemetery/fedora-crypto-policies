# A level that will provide security on a conservative level that is
# believed to withstand any near-term future attacks. That will be
# an 112-bit security level, without including protocols with known
# attacks available (e.g. SSL 3.0). This level may prevent communication
# with many used systems that provide weaker security levels (e.g.,
# systems that use SHA-1 as signature algorithm).

# MACs: SHA1+
# Curves: of size 256+ or better
# Signature algorithms: must use SHA-256 hash or better
# Ciphers: AES-GCM, AES-CCM, AES-CTR, AES-CBC, CAMELLIA-GCM, CAMELLIA-CBC
# Key exchange: ECDHE, RSA, DHE
# DH params size: 2048+
# RSA params size: 2048+
# Protocols: TLS1.2+

sub update_lists {

    @mac_list = ('AEAD', 'HMAC-SHA1', 'HMAC-SHA2-256', 'HMAC-SHA2-384', 'HMAC-SHA2-512');
    @curve_list = ('SECP256R1', 'SECP384R1', 'SECP521R1', 'X25519');
    @hash_list = ('SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA3-256', 'SHA3-384', 'SHA3-512');
    @sign_list = (
        'RSA-SHA2-224', 'DSA-SHA2-224', 'ECDSA-SHA2-224',
        'RSA-SHA2-256', 'DSA-SHA2-256', 'ECDSA-SHA2-256',
        'RSA-SHA2-384', 'DSA-SHA2-384', 'ECDSA-SHA2-384',
        'RSA-SHA2-512', 'DSA-SHA2-512', 'ECDSA-SHA2-512',
        'RSA-SHA3-256', 'DSA-SHA3-256', 'ECDSA-SHA3-256',
        'RSA-SHA3-384', 'DSA-SHA3-384', 'ECDSA-SHA3-384',
        'RSA-SHA3-512', 'DSA-SHA3-512', 'ECDSA-SHA3-512');

    @cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'CHACHA20-POLY1305', 'CAMELLIA-256-GCM',
        'AES-256-CTR', 'AES-256-CBC', 'CAMELLIA-256-CBC', 
        'AES-128-GCM', 'AES-128-CCM', 'CAMELLIA-128-GCM', 'AES-128-CTR', 'AES-128-CBC', 'CAMELLIA-128-CBC');
    @key_exchange_list = ('ECDHE', 'RSA', 'DHE', 'PSK', 'DHE-PSK', 'ECDHE-PSK');
    @protocol_list = ('TLS1.2', 'DTLS1.2');

    $min_tls_version = 'TLS1.2';
    $min_dtls_version = 'DTLS1.2';

    # Parameter sizes
    $min_dh_size = 2048;
    $min_dsa_size = 2048;
    $min_rsa_size = 2048;

    update_rev_lists();
}

update_lists();
