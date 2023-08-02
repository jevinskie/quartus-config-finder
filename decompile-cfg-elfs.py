#!/usr/bin/env python3

import subprocess
import sys

from path import Path

IDA_PATH = "/Applications/IDA Pro 7.7/idabin/idat64"

i = 0
for elf_full_filename in map(Path, open(sys.argv[1]).read().splitlines()):
    print(f"Decompiling {elf_full_filename.name}")
    c_file = elf_full_filename + ".c"
    try:
        args = [IDA_PATH, f"-Ohexrays:-nosave:{str(c_file)}:ALL", "-A", str(elf_full_filename)]
        print(f"running {' '.join(args)}")
        decomp_res = subprocess.run(
            [IDA_PATH, f"-Ohexrays:-nosave:{str(c_file)}:ALL", "-A", str(elf_full_filename)],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"failed to decompile {elf_full_filename} error: {e}")
        pass
