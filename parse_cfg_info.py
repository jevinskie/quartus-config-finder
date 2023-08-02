#!/usr/bin/env python3

import argparse
import sys

import lief
import wrapt
from rich import inspect, print


def get_cstring(b: lief.ELF.Binary, addr: int) -> str:
    cstr = bytearray()
    while True:
        byte = b.get_content_from_virtual_address(addr, 1)
        if byte[0] != 0:
            cstr.append(byte[0])
        else:
            return cstr.decode("utf-8")
        addr += 1


def get_str_pairs_from_ptr_table(b: lief.Binary, table_sym: str) -> dict[str, str]:
    ptr_sz = b._self_ptr_sz
    tbl = b.get_symbol(table_sym)
    assert tbl is not None
    str_pairs = {}
    for str_pair_first_ptr in range(tbl.value, tbl.value + tbl.size, 2 * ptr_sz):
        name_ptr = int.from_bytes(
            b.get_content_from_virtual_address(str_pair_first_ptr, ptr_sz), byteorder="little"
        )
        val_ptr = int.from_bytes(
            b.get_content_from_virtual_address(str_pair_first_ptr + ptr_sz, ptr_sz),
            byteorder="little",
        )
        str_pairs[get_cstring(b, name_ptr)] = get_cstring(b, val_ptr)
    if list(str_pairs)[-1] == "":
        del str_pairs[""]
    return str_pairs


def real_main(args):
    b = lief.parse(args.in_file)
    b = wrapt.ObjectProxy(b)
    assert isinstance(b, lief.ELF.Binary)
    b._self_ptr_sz = 8 if b.type == lief.ELF.ELF_CLASS.CLASS64 else 4
    enum_based_defaults = get_str_pairs_from_ptr_table(b, "cfg_enum_based_defaults")
    print(enum_based_defaults)
    user_ini_name_default_values = get_str_pairs_from_ptr_table(
        b, "cfg_user_ini_name_default_values"
    )
    print(user_ini_name_default_values)
    user_ini_name_old_name_table = get_str_pairs_from_ptr_table(
        b, "cfg_user_ini_name_old_name_table"
    )
    print(user_ini_name_old_name_table)


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="parse_cfg_info.py")
    parser.add_argument(
        "-i", "--in", dest="in_file", required=True, help="Input libccl_cfg_ini to parse"
    )
    parser.add_argument(
        "-o", "--out", required=True, default="-", dest="out_file", help="Output JSON path"
    )
    return parser


def main():
    args = get_arg_parser().parse_args()
    if args.out_file == "-":
        args.out_file = sys.stdout
    else:
        args.out_file = open(args.out_file, "w")
    real_main(args)


if __name__ == "__main__":
    main()
