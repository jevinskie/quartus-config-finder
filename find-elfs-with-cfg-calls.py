#!/usr/bin/env python3

# import sys

# from path import Path

# cfg_syms = open(sys.argv[3], "rb").read().splitlines()
# # print(cfg_syms)

# cfg_elfs = set()
# for filename in open(sys.argv[1]).read().splitlines():
#     fullpath = Path(sys.argv[2]) / Path(filename)
#     with open(fullpath, "rb") as f:
#         buf = f.read()
#         for sym in cfg_syms:
#             # if "libccl_cfg_ini.so" in str(fullpath):
#             #     print("found cfg lib itself")
#             #     if sym in buf:
#             #         print(f"found {sym}")
#             #     else:
#             #         print(f"no sym {sym}")
#             if sym in buf:
#                 cfg_elfs.add(fullpath)

# for elf in cfg_elfs:
#     print(elf)

#!/usr/bin/env python3

import argparse
import io
import sys
from typing import Optional, TypeVar

import lief
import wrapt
from path import Path
from rich import inspect, print
from tap import Tap
from typing_extensions import Self

ELF_MAGIC = b"\x7FELF"
CFG_ELF = Path("libccl_cfg_ini.so")


def real_main(args):
    elfs: list[Path] = []
    cfg_elf = Optional[Path]
    for f in args.in_path.walkfiles():
        if open(f, "rb").read(4) == ELF_MAGIC:
            print(f"{f} is ELF")


# class OpenedTextPath(io.TextIOWrapper):
#     def __init__(self, p: Path, mode: str = "r"):
#         # super
#         if mode not in ("r", "w"):
#             raise TypeError("mode must be \"r\" or \"w\"")
#         if p == "-":
#             if mode != "w":
#                 raise TypeError("mode for \"-\" (stdout) must be \"w\"")
#             return sys.stdout
#         return open(p, mode)


class TextOutputPath(Path):
    def __init__(self: Self, path: Path) -> None:
        super().__init__(path)

    @property
    def file(self: Self) -> io.TextIOWrapper:
        if not hasattr(self, "_file"):
            if self == "-":
                self._file: io.TextIOWrapper = sys.stdout
            else:
                self._file: io.TextIOWrapper = open(self, "w")
        return self._file

    @classmethod
    def to_text_output_path(cls: type(Self), path: Path) -> Self:
        return cls(path)


class Args(Tap):
    in_path: Path  # Input Quartus binary directory to search
    out_path: Path = "-"  # "Output JSON path (defaults to "-" for stdout)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, underscores_to_dashes=True, **kwargs)

    def configure(self):
        self.add_argument("-i", "--in_path")
        self.add_argument("-o", "--out_path", type=TextOutputPath.to_text_output_path)


def main():
    args = Args().parse_args()
    real_main(args)


if __name__ == "__main__":
    main()
