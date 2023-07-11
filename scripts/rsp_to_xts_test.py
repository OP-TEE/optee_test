#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2023 NXP
#

modes = {'encrypt': 0, 'decrypt': 1}

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

    if 'PT' not in myvars:
        myvars['PT'] = ''

    data_len = int(myvars['DataUnitLen'])
    # As describe in tee_do_cipher_update,
    # TEE_ALG_AES_XTS does not need padding but need a complete block on final
    # and minimum data size to one block.
    # As we cannot control the final input data size,
    # we only accept buffer size aligned on a block size.
    if data_len % 16 != 0:
        return

    if limited and nb_tc != 0:
        return

    nb_tc = nb_tc + 1

    outf.write('{ TEE_ALG_AES_XTS, ' + mode + ', TEE_TYPE_AES,\n')
    outf.write('/* Key1 */ ' + to_compound_str(myvars['Key1']) + '\n')
    outf.write('/* Key2 */ ' + to_compound_str(myvars['Key2']) + '\n')
    outf.write('/* IV  */ ' + to_compound_str(myvars['i']) + '\n')
    outf.write('0,\n')
    if mode == "TEE_MODE_ENCRYPT":
        outf.write('/* PT  */ ' + to_compound_str(myvars['PT']) + '\n')
        outf.write('/* CT  */ ' + to_compound_str(myvars['CT']) + '\n')
    else:
        outf.write('/* CT  */ ' + to_compound_str(myvars['CT']) + '\n')
        outf.write('/* PT  */ ' + to_compound_str(myvars['PT']) + '\n')
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
        if re.match('^\[', myl):
            continue
        s = re.split('\W+', myl)
        if len(s) == 0:
            continue
        name = s[0]
        if name == 'COUNT':
            if len(myvars) > 1:
                generate_case(outf, myvars, mode)
                myvars = {}
            myvars['Line'] = line_num

        if len(s) < 2:
            myvars[s[0]] = ''
        else:
            myvars[s[0]] = s[1]

        if len(s) < 2:
            continue
        val = s[1]

        if val == '00':
            myvars[s[0]] = ''

        if s[0] == 'Key':
            key_len = int(len(val)/2)
            myvars['Key1'] = val[0:key_len]
            myvars['Key2'] = val[key_len:len(val)]


    if len(myvars) > 1:
        generate_case(outf, myvars, mode)


if __name__ == "__main__":
    main()
