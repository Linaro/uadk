#!/usr/bin/python
#-*- coding: utf-8 -*-

import os
import os.path
import sys, getopt
import numpy as np
import tempfile

class listcontent(object):
    def __init__(self, ifile, ofile):
        self.ifile_nm = ifile
        self.ofile_nm = ofile
        self.ifile = open(ifile, "rb")
        self.ofile = open(ofile, "wb")
        # addr: 8 bytes, size: 8 bytes, next: 8 bytes
        #self.entry_sz = 0x18;
        self.entry_addr = 0;
        self.entry_size = 0;
        self.entry_next = 0;

    def __del__(self):
        self.ifile.close()
        self.ofile.close()

    def deflate(self, olist, blk_sz):
        ifile_sz = os.path.getsize(self.ifile_nm)
        count = (ifile_sz + int(blk_sz) - 1) / int(blk_sz)
        # Create array
        data = np.ndarray(count * 3, dtype=np.uint64)
        entries = data.reshape(-1, 3)
        i = 0
        while i < count:
            # Each block of data is stored in temporary file that is used
            # by gzip.
            f = tempfile.NamedTemporaryFile(delete=False)
            blk = self.ifile.read(int(blk_sz))
            f.write(blk)
            f.close()
            of = tempfile.NamedTemporaryFile(delete=False)
            of.close()
            os.system("gzip -c --fast < %s > %s" % (f.name, of.name))
            if not i:
                os.system("cat %s > %s" % (of.name, self.ofile_nm))
            else:
                os.system("cat %s >> %s" % (of.name, self.ofile_nm))
            # entries[i][0] should be the address of output buffer.
            # But the output is file now, not buffer. So fill it with
            # any non-zero value.
            entries[i][0] = 1
            entries[i][1] = os.path.getsize(of.name)
            if i == count - 1:
                entries[i][2] = 0
            else:
                entries[i][2] = 1
            i += 1
            os.remove(f.name)
            os.remove(of.name)
        entries.tofile(olist)

    # Read block data from ifile by ilist. And inflate each block data.
    def inflate(self, ilist):
        self.ilist_nm = ilist
        data = np.fromfile(self.ilist_nm, dtype=np.uint64)
        # Each entry contains addr, size and next fields
        # Convert data array into the two dimensional array
        entries = data.reshape(-1, 3)
        i = 0
        while i < entries.shape[0]:
            # Each block of data is stored in temporary file that is used
            # by gunzip.
            f = tempfile.NamedTemporaryFile(delete=False)
            blk = self.ifile.read(entries[i][1])
            f.write(blk)
            f.close()
            if not i:
                os.system("gunzip < %s > %s" % (f.name, self.ofile_nm))
            else:
                os.system("gunzip < %s >> %s" % (f.name, self.ofile_nm))
            os.remove(f.name)
            if not entries[i][2]:
                break
            i += 1

def sw_deflate(ifile, ofile, olist, blk_sz):
    dfl = listcontent(ifile, ofile)
    dfl.deflate(olist, blk_sz)

def sw_inflate(ifile, ofile, ilist):
    ifl = listcontent(ifile, ofile)
    ifl.inflate(ilist)

def main(argv):
    ilist = ''
    olist = ''
    ifile = ''
    ofile = ''
    blk_sz = 0
    try:
        opts, args = getopt.getopt(argv, "hb:", ["ilist=","olist=","in=","out="])
        for opt, arg in opts:
            if opt in ("-h"):
                print('Software deflate command:')
                print('    list_loader -b <block size> --in <file> --out <file> --olist <file>')
                print('Software inflate command:')
                print('    list_loader --in <file> --out <file> --ilist <file>')
                sys.exit()
            elif opt in ("-b"):
                blk_sz = arg
            elif opt in ("--ilist"):
                if not os.path.isfile(arg):
                    print("File does not exist:", arg)
                    sys.exit(1)
                ilist = arg
            elif opt in ("--olist"):
                olist = arg
            elif opt in ("--in"):
                if not os.path.isfile(arg):
                    print("File does not exist:", arg)
                    sys.exit(1)
                ifile = arg
            elif opt in ("--out"):
                ofile = arg
    except getopt.GetoptError:
        # Compress source to destination file and output list file
        print('Software deflate command:')
        print('    list_loader -b <block size> --in <file> --out <file> --olist <file>')
        # Decompress source to destination file with input list file
        print('Software inflate command:')
        print('    list_loader --in <file> --out <file> --ilist <file>')
        sys.exit(2)

    if blk_sz:
        sw_deflate(ifile, ofile, olist, blk_sz)
    else:
        sw_inflate(ifile, ofile, ilist)

if __name__ == "__main__":
    main(sys.argv[1:])
