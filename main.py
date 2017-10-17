#!/usr/bin/python

import argparse
from core.omlete import Omlete
from core.dump_sections import DumpSections
from core.opcode import Opcode


if __name__ == '__main__':
    # msfvenom -p windows/shell_bind_tcp -b '\x00' -f raw > shell.bin
    banner = "[+] Exploit Development Toolkit (EDT) [+]"
    banner += "\n"
    banner += \
        "[+] By motazreda https://github.com/motazreda @dangerousmind5 [+]"
    parser = argparse.ArgumentParser(
        description=banner,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-s',
        action="store",
        help="shellcode file <shell.bin>",
        type=str
    )
    parser.add_argument(
        '-c',
        action="store",
        help="chunk size",
        type=int
    )
    parser.add_argument(
        '-p',
        action="store",
        help="choose padding size",
        type=int
    )
    parser.add_argument(
        '-v',
        action="store",
        help="choose variable name",
        type=str
    )
    parser.add_argument(
        '-d',
        action="store",
        help="dump sections of pe file in files",
        type=str
    )
    parser.add_argument(
        '--dest',
        action="store",
        help="directory to store dumped sections files, used with -d option",
        type=str
    )
    parser.add_argument(
        '--op',
        action="store",
        help="translate opcode to assembly instructions",
        type=str
    )
    parser.add_argument(
        '--md',
        action="store",
        help="used with --op options to choose architecture",
        type=str
    )

    res = parser.parse_args()
    if res.s and res.c and res.p:
        om = Omlete(
            chunk_size=res.c,
            padding=res.p,
            tag=["\\x12", "\\x34", "\\x56", "\\x78"],
            shellcode=res.s,
            var_name=res.v
        )
        om.generate()
    elif res.d and res.dest:
        ds = DumpSections(res.d, res.dest)
        ds.dump_to_dir()
    elif res.op and res.md:
        m = Opcode(res.op, res.md)
        m.translate()
