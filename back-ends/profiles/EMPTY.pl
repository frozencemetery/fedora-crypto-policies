# A level for test purposes. It provides empty lists of allowed algorithms.

sub update_lists {

    @mac_list = ();
    @curve_list = ();
    @hash_list = ();
    @sign_list = ();

    @cipher_list = ();
    @key_exchange_list = ();
    @protocol_list = ();

    $min_tls_version = '';
    $min_dtls_version = '';

    # Parameter sizes
    $min_dh_size = 0;
    $min_dsa_size = 0;
    $min_rsa_size = 0;

    update_rev_lists();
}

update_lists();
