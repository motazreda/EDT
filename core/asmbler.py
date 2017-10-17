from keystone import *


class Asmbler(object):
    def __init__(self, code=None, mode=None):
        print "[+] assembler translator [+]"
        self.code = code
        self.mode = mode

    def asmble(self):
        if self.code:
            try:
                if self.mode == '32':
                    ks = Ks(KS_ARCH_X86, KS_MODE_32)
                elif self.mode == '64':
                    ks = Ks(KS_ARCH_X86, KS_MODE_64)
                enc, count = ks.asm(self.code)
                inst = [hex(i) for i in enc]
                print inst
            except KsError as e:
                print("Error %s" % e)
