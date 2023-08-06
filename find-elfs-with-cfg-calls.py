#!/usr/bin/env python3

import io
import json
import sys
from collections import defaultdict
from multiprocessing import Pool
from typing import Optional

import lief
from attrs import define
from cxxfilt import demangle
from path import Path
from rich import print
from tap import Tap
from typing_extensions import Self

ELF_MAGIC = b"\x7FELF"
CFG_ELF = Path("libccl_cfg_ini.so")


class TextOutputPath(Path):
    def __init__(self: Self, path: Path) -> None:
        super().__init__(path)

    @property
    def fh(self: Self) -> io.TextIOWrapper:
        if not hasattr(self, "_fh"):
            if self == "-":
                self._fh: io.TextIOWrapper = sys.stdout
            else:
                self._fh: io.TextIOWrapper = open(self, "w")
        return self._fh

    @classmethod
    def to_text_output_path(cls: type(Self), path: Path) -> Self:
        return cls(path)


class Args(Tap):
    in_dir: Path  # Input Quartus binary directory to search
    out_json: Path = "-"  # "Output JSON path (defaults to "-" for stdout)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, underscores_to_dashes=True, **kwargs)

    def configure(self):
        self.add_argument("-i", "--in_dir")
        self.add_argument("-o", "--out_json", type=TextOutputPath.to_text_output_path)


def demangle_syms(syms: list[str]) -> list[str]:
    return sorted([demangle(s) for s in syms])


def get_cfg_exports(cfg_elf: Path) -> list[str]:
    b = lief.parse(cfg_elf)
    if not isinstance(b, lief.ELF.Binary):
        raise TypeError(f"cfg_elf ({cfg_elf.name()}) is not a lief.ELF.Binary")
    return sorted({s.name for s in b.exported_symbols if "cfg" in s.name})


def elf_imported_cfg_exports(elf_path: Path, cfg_exports_set: set[str]) -> list[str]:
    b = lief.parse(elf_path)
    if not isinstance(b, lief.ELF.Binary):
        raise TypeError(f"{elf_path.name()} is not a lief.ELF.Binary")
    imp_syms = {s.name for s in b.symbols}
    return sorted(imp_syms.intersection(cfg_exports_set))


@define
class CfgUsingElf:
    path: Path
    cfg_sym_imports: list[str]
    cfg_sym_imports_demangled: list[str]

    def to_dict(self: Self) -> dict:
        return {
            "path": self.path,
            "cfg_syms": self.cfg_sym_imports,
            "cfg_syms_demangled": self.cfg_sym_imports_demangled,
        }


def write_cfg_using_elfs_json(
    cfg_exports: list[str],
    cfg_exports_demangled: list[str],
    cfg_using_elfs: list[CfgUsingElf],
    out_json: TextOutputPath,
) -> None:
    info = {}
    info["cfg_exports"] = cfg_exports
    info["cfg_exports_demangled"] = cfg_exports_demangled
    info["num_cfg_using_elfs"] = len(cfg_using_elfs)
    num_elfs_using_sym = defaultdict(int)
    num_elfs_using_sym_demangled = defaultdict(int)
    for e in cfg_using_elfs:
        for s in e.cfg_sym_imports:
            num_elfs_using_sym[s] += 1
        for ds in e.cfg_sym_imports_demangled:
            num_elfs_using_sym_demangled[ds] += 1
    num_elfs_using_sym = dict(
        sorted(num_elfs_using_sym.items(), key=lambda p: p[1], reverse=True)
    )
    num_elfs_using_sym_demangled = dict(
        sorted(num_elfs_using_sym_demangled.items(), key=lambda p: p[1], reverse=True)
    )
    info["num_elfs_using_sym"] = num_elfs_using_sym
    info["num_elfs_using_sym_demangled"] = num_elfs_using_sym_demangled
    info["cfg_using_elfs"] = list(map(lambda e: e.to_dict(), cfg_using_elfs))
    json.dump(info, out_json.fh, indent=4)
    out_json.fh.flush()


@define
class InspectArgs:
    path: Path
    cfg_elf: Path
    cfg_exports_set: set[str]


def inspect_cfg_using_elf(args: InspectArgs) -> Optional[CfgUsingElf]:
    if args.path == args.cfg_elf:
        return None
    with open(args.path, "rb") as fh:
        if fh.read(len(ELF_MAGIC)) != ELF_MAGIC:
            return None
    print(f"inspecting ELF {args.path}")
    used_cfg_exports: list[str] = elf_imported_cfg_exports(
        args.path, args.cfg_exports_set
    )
    if used_cfg_exports:
        print(f"{args.path.name} uses cfg syms")
        used_cfg_exports_demangled: list[str] = demangle_syms(used_cfg_exports)
        return CfgUsingElf(args.path, used_cfg_exports, used_cfg_exports_demangled)
    return None


def real_main(args: Args) -> None:
    cfg_elf: Optional[Path] = None
    for f in args.in_dir.walkfiles():
        with open(f, "rb") as fh:
            if fh.read(len(ELF_MAGIC)) == ELF_MAGIC:
                if f.name == CFG_ELF:
                    cfg_elf = f
                    break
    if cfg_elf is None:
        raise LookupError(f"Couldn't find {CFG_ELF}")
    cfg_exports: list[str] = get_cfg_exports(cfg_elf)
    cfg_exports_demangled: list[str] = demangle_syms(cfg_exports)
    cfg_exports_set: set[str] = set(cfg_exports)
    cfg_exports_set_demangled: set[str] = set(cfg_exports_demangled)
    if len(cfg_exports_demangled) != len(cfg_exports_set_demangled):
        raise ValueError(
            f"len(cfg_exports_demangled) = {len(cfg_exports_demangled)} != len(cfg_exports_demangled) = {len(cfg_exports_set_demangled)}"
        )
    print(cfg_exports, file=open("cfg-exports.txt", "w"))
    print(cfg_exports_demangled, file=open("cfg-exports-demangled.txt", "w"))

    inspect_args: list[InspectArgs] = []
    for f in args.in_dir.walkfiles():
        inspect_args.append(InspectArgs(f, cfg_elf, cfg_exports_set))
    with Pool() as p:
        inspect_res = p.map(inspect_cfg_using_elf, inspect_args)
    cfg_using_elfs: list[CfgUsingElf] = list(
        filter(lambda r: r is not None, inspect_res)
    )
    cfg_using_elfs.sort(key=lambda e: e.path.name)
    print(cfg_using_elfs)
    write_cfg_using_elfs_json(
        cfg_exports, cfg_exports_demangled, cfg_using_elfs, args.out_json
    )


def main() -> None:
    args = Args().parse_args()
    real_main(args)


if __name__ == "__main__":
    main()
