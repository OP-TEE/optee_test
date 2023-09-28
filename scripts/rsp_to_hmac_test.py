#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2023 NXP
#

limited = False
nb_tc = 0

def to_compound_str(val):
    assert len(val) % 2 == 0, "Only even sized values supported"
    if len(val) > 0:
        import re
        a = re.findall('..', val)
        b = "(const uint8_t []){"
        for s in a:
            b += "0x" + s + ", "
        b += "}, " + repr(len(val) / 2) + ","
    else:
        b = "NULL, 0,"
    return b


def generate_case(outf, myvars, algo):
    global nb_tc

    if algo == "SHA1":
        # hashsize is 20 bytes
        if int(myvars['Tlen']) != 20:
            return
        # SHA1 maximum key size is 512 bits
        if int(myvars['Klen']) > 64:
            return
    elif algo == "SHA224":
        # hashsize is 28 bytes
        if int(myvars['Tlen']) != 28:
            return
        # SHA224 maximum key size is 512 bits
        if int(myvars['Klen']) > 64:
            return
    elif algo == "SHA256":
        # hashsize is 32 bytes
        if int(myvars['Tlen']) != 32:
            return
        # SHA256 maximum key size is 1024 bits
        if int(myvars['Klen']) > 128:
            return
    elif algo == "SHA384":
        # hashsize is 48 bytes
        if int(myvars['Tlen']) != 48:
            return
        # SHA384 maximum key size is 1024 bits
        if int(myvars['Klen']) > 128:
            return
    elif algo == "SHA512":
        # hashsize is 64 bytes
        if int(myvars['Tlen']) != 64:
            return
        # SHA512 maximum key size is 1024 bits
        if int(myvars['Klen']) > 128:
            return

    if limited and nb_tc != 0:
        return

    nb_tc = nb_tc + 1

    outf.write('{ TEE_ALG_HMAC_' + algo + ', TEE_TYPE_HMAC_' + algo + ',\n')
    outf.write('/* Key */ ' + to_compound_str(myvars['Key']) + '\n')
    outf.write('0,\n')
    outf.write('/* Msg */ ' + to_compound_str(myvars['Msg']) + '\n')
    outf.write('/* Mac  */ ' + to_compound_str(myvars['Mac']) + '\n')
    outf.write('false },\n')


def get_args():
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('--inf', required=True,
                        type=argparse.FileType('r'),
                        help='Name of input RSP file')

    parser.add_argument('--outf', required=True,
                        type=argparse.FileType('w'),
                        help='Name of output C file')

    parser.add_argument('--limited', action="store_true",
                        help='Only run one test case from each group')

    return parser.parse_args()


def main():
    import re
    global limited
    args = get_args()
    inf = args.inf
    outf = args.outf
    myvars = {}

    algo = "SHA1"
    limited = args.limited

    for line in inf:
        myl = line.strip()
        if len(myl) == 0:
            continue
        if re.match('^#', myl):
            continue
       	s = re.split('\W+', myl)
       	s = list(filter(None, s))
        if len(s) == 0:
            continue
        name = s[0]

        if name == 'L':
        	if s[1] == '20':
        		algo = "SHA1"
        	elif s[1] == '28':
        		algo = "SHA224"
        	elif s[1] == '32':
        		algo = "SHA256"
        	elif s[1] == '48':
        		algo = "SHA384"
        	elif s[1] == '64':
        		algo = "SHA512"
        	continue

        if name == 'Count':
            if len(myvars) > 1:
                generate_case(outf, myvars, algo)
                myvars = {}

        if len(s) < 2:
            myvars[s[0]] = ''
        else:
            myvars[s[0]] = s[1]

        if len(s) < 2:
            continue
        val = s[1]

        if val == '00':
            myvars[s[0]] = ''

    if len(myvars) > 1:
        generate_case(outf, myvars, algo)


if __name__ == "__main__":
    main()
