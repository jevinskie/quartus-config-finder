#!/usr/bin/env python3

import json
import subprocess
from multiprocessing import Pool

from path import Path
from rich import print
from tap import Tap

IDA_PATH = "/Applications/IDA Pro 7.7/idabin/idat64"


class Args(Tap):
    in_json: Path  # Input cfg-using-elfs.json path
    out_dir: Path  # "Output directory for cfg using ELFs

    def __init__(self, *args, **kwargs):
        super().__init__(*args, underscores_to_dashes=True, **kwargs)

    def configure(self):
        self.add_argument("-i", "--in_json")
        self.add_argument("-o", "--out_dir")


def get_orig_paths_to_cfg_using_elfs(json_path: Path) -> list[Path]:
    with open(json_path) as fh:
        info = json.load(fh)
    cfg_using_elfs: list[Path] = []
    for elf in info["cfg_using_elfs"]:
        cfg_using_elfs.append(Path(elf["path"]))
    return cfg_using_elfs


def copy_elfs(orig_elfs: list[Path], out_dir: Path) -> list[Path]:
    copied_elfs: list[Path] = []
    for orig_elf in orig_elfs:
        copied_elfs.append(orig_elf.copy(out_dir))
    return copied_elfs


def decompile_elf(elf_path: Path) -> None:
    print(f"Decompiling {elf_path.name}")
    c_file = elf_path + ".c"
    args = [
        IDA_PATH,
        f"-Ohexrays:-nosave:{c_file}:ALL",
        "-A",
        elf_path,
    ]
    print(f"running {' '.join(args)}")
    try:
        decomp_res = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to decompile {elf_path} error: {e}")
        print(f"Output from failed command:\n{decomp_res.stdout}")


def real_main(args: Args) -> None:
    orig_cfg_using_elfs: list[Path] = get_orig_paths_to_cfg_using_elfs(args.in_json)
    args.out_dir.mkdir()
    copied_elfs = copy_elfs(orig_cfg_using_elfs, args.out_dir)
    with Pool() as p:
        p.map(decompile_elf, copied_elfs)


def main() -> None:
    args = Args().parse_args()
    real_main(args)


if __name__ == "__main__":
    main()
