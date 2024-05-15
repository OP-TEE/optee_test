#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2024 NXP
#

import json

modes = {'encrypt': 0, 'decrypt': 1}


def to_compound_str(name, val):
    assert len(val) % 2 == 0, "Only even sized values supported"
    if len(val) > 0:
        import re
        a = re.findall('..', val)
        b = name + " = (const uint8_t []){ "
        for s in a:
            b += "0x" + s + ", "
        b += "},\n\t" + name + "_len = " + repr((int)(len(val) / 2)) + ","
    else:
        b = name + " = NULL,\n\t" + name + "_len = 0,"
    return b


def generate_case(outf, tv, mode):
    outf.write('{\n\t.algo = TEE_ALG_AES_GCM, .mode = ' + mode +
               ', .key_type = TEE_TYPE_AES,\n')
    outf.write('\t' + to_compound_str('.key', tv['key']) + '\n')
    outf.write('\t' + to_compound_str('.nonce', tv['iv']) + '\n')
    outf.write('\t.aad_incr = 0,\n')
    outf.write('\t' + to_compound_str('.aad', tv['aad']) + '\n')
    outf.write('\t.in_incr = 0,\n')
    outf.write('\t' + to_compound_str('.ptx', tv['msg']) + '\n')
    outf.write('\t' + to_compound_str('.ctx', tv['ct']) + '\n')
    outf.write('\t' + to_compound_str('.tag', tv['tag']) + '\n')
    outf.write('\t.line = __LINE__,\n')
    outf.write('\t.id = ' + repr(tv['tcId']) + '\n},\n')


def get_args():
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('--inf', required=True,
                        type=argparse.FileType('r'),
                        help='Name of input json file')

    parser.add_argument('--outf', required=True,
                        type=argparse.FileType('w'),
                        help='Name of output C file')

    parser.add_argument('--mode', required=True, choices=modes.keys(),
                        help='mode: encrypt or decrypt')

    return parser.parse_args()


# Convert google/wycheproof AES GCM test vectors to xtest AE test cases
def main():
    args = get_args()
    inf = args.inf
    outf = args.outf

    outf.write("/* SPDX-License-Identifier: Apache-2.0 */\n")
    outf.write("/*\n")
    outf.write(" * Copyright 2024 NXP\n")
    outf.write(" */\n\n")

    if args.mode == "encrypt":
        mode = "TEE_MODE_ENCRYPT"
    else:
        mode = "TEE_MODE_DECRYPT"

    data = json.load(inf)

    for tg in data['testGroups']:
        for tv in tg['tests']:
            if tv['result'] == 'valid' and 'CounterWrap' in tv['flags']:
                generate_case(outf, tv, mode)


if __name__ == "__main__":
    main()
