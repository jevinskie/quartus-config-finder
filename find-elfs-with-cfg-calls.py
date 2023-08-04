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
from typing import TypeVar

import lief
import wrapt
from path import Path
from rich import inspect, print
from tap import Tap
from typing_extensions import Self

ELF_MAGIC = b"\x7FELF"
CFG_ELF = Path("libccl_cfg_ini.so")

# def real_main(args):
#     elfs: list[Path] = []
#     cfg_elf = Optional[None]
#     for f in args.in_path.walkfiles():
#         if open(f, "rb").read(4) == ELF_MAGIC:
#             pass

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


# OptionalStdoutPathType = TypeVar('OptionalStdoutPathType', bound='OptionalStdoutPath')
class OptionalStdoutPath(Path):
    file: io.TextIOWrapper

    def __init__(self: Self, path: Path) -> None:
        super().__init__(path)
        if self == "-":
            print("found -")
            self.file = sys.stdout
        else:
            self.file = open(path, "w")

    @classmethod
    def to_optional_stdout_path(cls: type(Self), path: Path) -> Self:
        return cls(path)


class Args(Tap):
    in_path: Path  # Input Quartus binary directory to search
    out: Path = "-"  # "Output JSON path (defaults to "-" for stdout)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, underscores_to_dashes=True, **kwargs)

    def configure(self):
        self.add_argument("-i", "--in_path")
        self.add_argument("-o", "--out", type=OptionalStdoutPath.to_optional_stdout_path)


args = Args().parse_args()
print(args)
print(args.out)
print(args.out.file)
print(type(args.out))
print(type(args.out).mro())

sys.exit(0)

# def get_arg_parser() -> argparse.ArgumentParser:
#     parser = argparse.ArgumentParser(description="find-elfs-with-cfg-calls.py")
#     parser.add_argument(
#         "-i", "--in-dir", required=True, help="Input Quartus binary directory to search"
#     )
#     parser.add_argument(
#         "-o", "--out", required=True, default="-", dest="out_file", help="Output JSON path"
#     )
#     return parser


# def main():
#     args = get_arg_parser().parse_args()
#     args.in_dir = Path(args.in_dir)
#     if args.out_file == "-":
#         args.out_file = sys.stdout
#     else:
#         args.out_file = open(args.out_file, "w")
#     real_main(args)


# if __name__ == "__main__":
#     main()
