#!/usr/bin/env python3

import sys

from path import Path

cfg_syms = open(sys.argv[3], "rb").read().splitlines()
# print(cfg_syms)

cfg_elfs = set()
for filename in open(sys.argv[1]).read().splitlines():
    fullpath = Path(sys.argv[2]) / Path(filename)
    with open(fullpath, "rb") as f:
        buf = f.read()
        for sym in cfg_syms:
            # if "libccl_cfg_ini.so" in str(fullpath):
            #     print("found cfg lib itself")
            #     if sym in buf:
            #         print(f"found {sym}")
            #     else:
            #         print(f"no sym {sym}")
            if sym in buf:
                cfg_elfs.add(fullpath)

for elf in cfg_elfs:
    print(elf)
