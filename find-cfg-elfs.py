#!/usr/bin/env python3

import sys

from path import Path

for filename in open(sys.argv[1]).read().splitlines():
    fullpath = Path(sys.argv[2]) / Path(filename)
    with open(fullpath, "rb") as f:
        if b"libccl_cfg_ini.so" in f.read():
            print(fullpath)
