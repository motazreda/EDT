import os
import sys
import pefile


class DumpSections(object):
    def __init__(self, pe_file, dest=None):
        print "[+] Loading PE File \n"
        self.pe_file = pe_file
        self.dest = dest

    def retreive_sections(self):
        pe = pefile.PE(self.pe_file, fast_load=True)
        secs = {}
        for section in pe.sections:
            secs[
                self.pe_file + "_" + section.Name
                .title()
                .replace("\x00", "")
            ] = section.get_data()
        return secs

    def dump_to_dir(self):
        if self.dest:
            if os.path.isdir(self.dest):
                print "directory exists, please choose not exist folder name"
                sys.exit(0)
            else:
                os.mkdir(self.dest)
                for sec in self.retreive_sections():
                    f = open(str(self.dest) + "/" + str(sec), "w+")
                    f.write(self.retreive_sections()[sec])
                    f.close()
