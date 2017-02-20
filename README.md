This repository contains the crypto-policies data and scripts used in
Fedora.

|Release|Status|
|:-----:|:----:|
|F25|[![build status](https://gitlab.com/nmav/fedora-crypto-policies/badges/master/build.svg)](https://gitlab.com/nmav/fedora-crypto-policies/commits/master)|

# Purpose

The purpose is to unify the crypto policies used by different applications
and libraries. That is allow setting a consistent security level for crypto
on all applications in a Fedora system, irrespective of the crypto library
in use.

# Description

The idea is to have few predefined security policies such as LEGACY, DEFAULT
and FUTURE which are set system-wide by the administrator. Then applications
that have no special needs will follow these policies by default. That
way the management of the various crypto applications and libraries used in a
system simplifies significantly.

The current implementations works by setting the desired policy in
/etc/crypto-policies/config. After this file is changed the script
'update-crypto-policies' should be executed, and the new policies
will activate.

The supported back ends in Fedora are:
 * GnuTLS
 * OpenSSL
 * BIND
 * libkrb5
 * OpenSSH (client)
 * Java via OpenJDK

The documentation of crypto policies is at [update-crypto-policies.8.txt](update-crypto-policies.8.txt).

