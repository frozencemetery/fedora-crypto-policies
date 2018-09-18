# Only FIPS approved or allowed algorithms. It does not provide FIPS compliace
# by itself, the FIPS validated crypto modules must be properly installed
# and the machine must be booted into the FIPS mode.

# MACs: all HMAC with SHA1 or better
# Curves: all prime >= 256 bits
# Signature algorithms: with SHA256 hash or better (not DSA)
# TLS Ciphers: >= 128-bit key, >= 128-bit block (AES, including AES-CBC)
# non-TLS Ciphers: same
# key exchange: ECDHE, DHE (not DHE-DSS)
# DH params size: >= 2048
# RSA params size: >= 2048
# TLS protocols: TLS >= 1.2

sub update_lists {

    @mac_list = ('AEAD', 'HMAC-SHA2-256', 'HMAC-SHA1', 'HMAC-SHA2-384', 'HMAC-SHA2-512');
    @group_list = ('SECP256R1', 'SECP384R1', 'SECP521R1',
        'FFDHE-2048', 'FFDHE-3072', 'FFDHE-4096', 'FFDHE-6144', 'FFDHE-8192');
    @hash_list = ('SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA3-256', 'SHA3-384', 'SHA3-512');
    @sign_list = (
        'RSA-SHA2-256', 'ECDSA-SHA2-256',
        'RSA-SHA2-384', 'ECDSA-SHA2-384',
        'RSA-SHA2-512', 'ECDSA-SHA2-512',
        'RSA-SHA3-256', 'ECDSA-SHA3-256',
        'RSA-SHA3-384', 'ECDSA-SHA3-384',
        'RSA-SHA3-512', 'ECDSA-SHA3-512',
        'RSA-PSS-SHA2-256', 'RSA-PSS-SHA2-384', 'RSA-PSS-SHA2-512',
        'RSA-SHA2-224', 'ECDSA-SHA2-224');

    @tls_cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'AES-256-CTR', 'AES-256-CBC',
        'AES-128-GCM', 'AES-128-CCM', 'AES-128-CTR', 'AES-128-CBC');
    @cipher_list = @tls_cipher_list;

    @key_exchange_list = ('ECDHE', 'DHE', 'DHE-RSA', 'PSK', 'DHE-PSK', 'ECDHE-PSK');

    @protocol_list = ('TLS1.2', 'DTLS1.2');
    @ike_protocol_list = ('IKEv2');

    $min_tls_version = 'TLS1.2';
    $min_dtls_version = 'DTLS1.2';

    # Parameter sizes
    $min_dh_size = 2048;
    $min_dsa_size = 2048;
    $min_rsa_size = 2048;

    update_rev_lists();
}

update_lists();
