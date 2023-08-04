#!/usr/bin/env python3

import io
import sys
from typing import Optional

import lief
from attrs import define
from cxxfilt import demangle
from path import Path
from rich import inspect, print
from tap import Tap
from typing_extensions import Self

ELF_MAGIC = b"\x7FELF"
CFG_ELF = Path("libccl_cfg_ini.so")


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


def get_cfg_exports(cfg_elf: Path) -> list[str]:
    b = lief.parse(cfg_elf)
    if not isinstance(b, lief.ELF.Binary):
        raise TypeError(f"cfg_elf ({cfg_elf.name()}) is not a lief.ELF.Binary")
    return sorted(set([s.name for s in b.exported_symbols if "cfg" in s.name]))


def elf_imported_cfg_exports(elf_path: Path, cfg_exports_set: set[str]) -> set[str]:
    b = lief.parse(elf_path)
    if not isinstance(b, lief.ELF.Binary):
        raise TypeError(f"{elf_path.name()} is not a lief.ELF.Binary")
    imp_syms = {s.name for s in b.symbols}
    return imp_syms.intersection(cfg_exports_set)


@define
class CfgUsingElf:
    path: Path
    cfg_sym_imports: list[str]
    cfg_sym_imports_demangled: list[str]


def pretty_print_cfg_using_elfs(
    cfg_using_elfs: list[CfgUsingElf], cfg_exports: list[str], out_path: TextOutputPath
) -> None:
    info = {}
    info["num_cfg_using_elfs"] = len(cfg_using_elfs)
    sym_used_n_times = [0] * len(cfg_exports)


def real_main(args) -> None:
    cfg_using_elfs: list[CfgUsingElf] = []
    cfg_elf: Optional[Path] = None
    for f in args.in_path.walkfiles():
        if open(f, "rb").read(len(ELF_MAGIC)) == ELF_MAGIC:
            if f.name == CFG_ELF:
                cfg_elf = f
                break
    if cfg_elf is None:
        raise LookupError("Couldn't find {CFG_ELF}")
    cfg_exports: list[str] = get_cfg_exports(cfg_elf)
    cfg_exports_demangled: list[str] = sorted([demangle(s) for s in cfg_exports])
    cfg_exports_set: set[str] = set(cfg_exports)
    cfg_exports_set_demangled: set[str] = set(cfg_exports_demangled)
    if len(cfg_exports_demangled) != len(cfg_exports_set_demangled):
        raise ValueError(
            f"len(cfg_exports_demangled) = {len(cfg_exports_demangled)} != len(cfg_exports_demangled) = {len(cfg_exports_set_demangled)}"
        )
    print(cfg_exports, file=open("cfg_exports.txt", "w"))
    print(cfg_exports_demangled, file=open("cfg_exports_demangled.txt", "w"))
    for f in args.in_path.walkfiles():
        if open(f, "rb").read(len(ELF_MAGIC)) == ELF_MAGIC:
            print(f"inspecting {f}")
            if f.name == CFG_ELF:
                continue
            used_cfg_exports: set[str] = elf_imported_cfg_exports(f, cfg_exports_set)
            if len(used_cfg_exports):
                print(f"{f.name} uses cfg syms")
                used_cfg_exports: list[str] = sorted(used_cfg_exports)
                used_cfg_exports_demangled: list[str] = sorted(
                    [demangle(s) for s in used_cfg_exports]
                )
                cfg_using_elfs.append(
                    CfgUsingElf(
                        path=f,
                        cfg_sym_imports=used_cfg_exports,
                        cfg_sym_imports_demangled=used_cfg_exports_demangled,
                    )
                )
    print(cfg_using_elfs)


class Args(Tap):
    in_path: Path  # Input Quartus binary directory to search
    out_path: Path = "-"  # "Output JSON path (defaults to "-" for stdout)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, underscores_to_dashes=True, **kwargs)

    def configure(self):
        self.add_argument("-i", "--in_path")
        self.add_argument("-o", "--out_path", type=TextOutputPath.to_text_output_path)


def main() -> None:
    args = Args().parse_args()
    real_main(args)


if __name__ == "__main__":
    main()
