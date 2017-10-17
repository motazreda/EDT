import sys
from capstone import *
import binascii


class Opcode(object):
    def __init__(self, opcode=None, mode=None):
        print "[+] Opcode Translation [+]"
        self.opcode = opcode
        self.mode = mode

    def translate(self):
        if self.mode == '32':
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif self.mode == '64':
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            print("Please choose supported arch, 32 or 64")
            sys.exit(0)
        opcode_list = [binascii.unhexlify(he) for he in self.opcode.split(" ")]
        code = b"".join(opcode_list)
        for i in md.disasm(code, 0x0):
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
