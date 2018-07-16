#!/usr/bin/python3

import os
import subprocess
import sys
import tempfile

# krb5check can be found at:
#     https://github.com/frozencemetery/krb5check
# At a minimum, it verifies that:
#   - no unrecognized sections are specified
#   - no values are overriding each other
#   - libdefaults section is present
#   - permitted_enctypes is specified
#   - no unknown enctypes are specified
#   - no known-broken enctypes are specified
#   - if pkinit_dh_min_bits is specified, it is larger than default
#   - if pkinit_dh_min_bits is specified, it is reasonable

try:
    from krb5check.krb5_conf import parse, check
    pass
except:
    print("Skipping krb5 test; checker not found!", file=sys.stderr)
    exit(0)

# Don't verify EMPTY policy
for policy in ["LEGACY", "DEFAULT", "FUTURE", "FIPS"]:
    perl = """
        use lib "./back-ends/";
        require "./back-ends/krb5.pl";
        print generate_temp_policy("%s", "", "./back-ends");
    """ % policy
    data = subprocess.check_output(["perl", "-e", perl],
                                   stderr=subprocess.STDOUT)
    data = data.decode("utf-8")
    data = data.replace("\\n", "\n") # what

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data.encode("utf-8"))
        path = f.name
        pass
    
    sections = parse(path)
    check(sections)

    os.unlink(path)
    pass
