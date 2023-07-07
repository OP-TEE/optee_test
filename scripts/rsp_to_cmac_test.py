#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2023 NXP
#

modes = {'generate': 0, 'verify': 1}

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


def generate_case(outf, myvars, mode):
    global nb_tc

    if 'Result' in myvars and myvars['Result'] != 'P':
        return
    # TEE_ALG_AES_CMAC supported digest size is
    # size of an AES block.
    if int(myvars['Tlen']) != 16:
        return

    if limited and nb_tc != 0:
        return

    nb_tc = nb_tc + 1

    outf.write('{ TEE_ALG_AES_CMAC, TEE_TYPE_AES,\n')
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

    parser.add_argument('--mode', required=True, choices=modes.keys(),
                        help='mode: generate or verify')

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

    if args.mode == "generate":
        mode = "TEE_MODE_SIGN"
    else:
        mode = "TEE_MODE_VERIFY"

    limited = args.limited

    for line in inf:
        myl = line.strip()
        if len(myl) == 0:
            continue
        if re.match('^#', myl):
            continue
        if re.match('^\[', myl):
            continue
        s = re.split('\W+', myl)
        if len(s) == 0:
            continue
        name = s[0]
        if name == 'Count':
            if len(myvars) > 1:
                generate_case(outf, myvars, mode)
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
        generate_case(outf, myvars, mode)


if __name__ == "__main__":
    main()
