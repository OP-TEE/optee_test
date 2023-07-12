#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2023 NXP
#

modes = {'encrypt': 0, 'decrypt': 1}

limited = False

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


def generate_case(outf, myvars, mode):
    if limited and myvars['Count'] != '0':
        return

    outf.write('{ TEE_ALG_AES_CCM, ' + mode + ', TEE_TYPE_AES,\n')
    outf.write('/* Key */ ' + to_compound_str(myvars['Key']) + '\n')
    outf.write('/* Nonce */ ' + to_compound_str(myvars['Nonce']) + '\n')
    outf.write('0,\n')
    outf.write('/* AAD */ ' + to_compound_str(myvars['Adata']) + '\n')
    outf.write('0,\n')
    if mode == "TEE_MODE_ENCRYPT":
        outf.write('/* Payload */ ' + to_compound_str(myvars['Payload']) + '\n')
    outf.write('/* CT  */ ' + to_compound_str(myvars['CT']) + '\n')
    if mode == "TEE_MODE_DECRYPT":
        outf.write('/* Payload  */ ' + to_compound_str(myvars['Payload']) + '\n')
    outf.write('/* Tag */ ' + to_compound_str(myvars['Tag']) + '\n')
    outf.write(repr(myvars['Line']) + '},\n')


def get_args():
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('--inf', required=True,
                        type=argparse.FileType('r'),
                        help='Name of input RSP file')

    parser.add_argument('--outf', required=True,
                        type=argparse.FileType('a'),
                        help='Name of output C file')

    parser.add_argument('--mode', required=True, choices=modes.keys(),
                        help='mode: encrypt or decrypt')

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
    line_num = 0

    if args.mode == "encrypt":
        mode = "TEE_MODE_ENCRYPT"
    else:
        mode = "TEE_MODE_DECRYPT"

    limited = args.limited

    for line in inf:
        line_num += 1
        myl = line.strip()
        if len(myl) == 0:
            continue
        if re.match('^#', myl):
            continue
        s = re.split('\W+', myl)
        if len(s) == 0:
            continue
        s = [x for x in s if x != '']
        name = s[0]
        if name == 'Count':
            myvars['Line'] = line_num

        if len(s) < 2:
            myvars[s[0]] = ''

        while len(s) >= 2:
            val = s[1]

            if val == '00':
                myvars[s[0]] = ''
            elif s[0] == 'CT':
                if myvars['Tlen'] != 0:
                    ct_len = int(len(val) - int(myvars['Tlen']) * 2)
                    myvars['CT'] = val[0:ct_len]
                    myvars['Tag'] = val[ct_len:len(val)]
                else:
                    myvars['Tag'] = ''
            else:
                myvars[s[0]] = s[1]
            s = s[2:]

        if 'CT' in myvars:
            generate_case(outf, myvars, mode)
            myvars.pop('CT')


if __name__ == "__main__":
    main()
