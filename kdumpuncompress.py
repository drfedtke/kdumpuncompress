#!/usr/bin/env python3

##
##---------------------------------------------------------------------------##
##
## This is kdumpuncompress.py  --  convert LZO or ZLIB compressed linux kdumps 
##                                 into raw kdumps
##
##
## Copyright (C) 2016-2022 by  Dr. Stephen Fedtke,  System Software
##
## KdumpUncompress is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation; either version 2 of
## the License, or (at your option) any later version.
##
## KdumpUncompress is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with KdumpUncompress; see the file COPYING.
## If not, write to the Free Software Foundation, Inc.,
## 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
##
## Worldwide phone number: 00800-DRFEDTKE or 00800-37333853
##
##---------------------------------------------------------------------------##


import platform
import sys
from hexdump import hexdump
from enum import Enum
import zlib

import lzo
import numpy as np


if '-h' in sys.argv:
    print("""
    *****************************************************************

            Copyright
            =========

            KdumpUncompress is Copyright (C) 2016-2022
            by  Dr. Stephen Fedtke,  System Software

            KdumpUncompress is distributed under the terms of the
            GNU General Public License (GPL). See the file NOTICE.


            This software includes:

                 Python-LZO -- Python bindings for LZO

              Copyright (c) 1996-2002 Markus F.X.J. Oberhumer
                          <markus@oberhumer.com>
                 http://www.oberhumer.com/opensource/lzo/
              Copyright (c) 2011-2016 Joshua D. Boyd
                          <jdboyd@jdboyd.net>
                 https://github.com/jd-boyd/python-lzo

            Worldwide phone number: 00800-DRFEDTKE or 00800-37333853

    *****************************************************************

    usage:    
                kdumpuncompress.py  <dump.in>  <dump.out>  [options]
    purpose:  
                uncompress linux kdumps to raw kdump format
    options:    
                -v  be verbose
                -h  this help

    """)
    raise SystemExit




DiskDumpHeader64 =  np.dtype([
    ("signature"         , np.dtype('S'), 8   ),  # 'KDUMP   '
    ("header_version"    , np.uint32          ),
    ("sysname"           , np.dtype('S65')    ),
    ("nodename"          , np.dtype('S65')    ),
    ("release"           , np.dtype('S65')    ),
    ("version"           , np.dtype('S65')    ),
    ("machine"           , np.dtype('S65')    ),
    ("domainname"        , np.dtype('S65')    ),
    #("utsname"           , np.dtype('S65'), 6 ),
    ("timestamp"         , np.byte      ,(22,)),
    ("status"            , np.uint32          ),
    ("block_size"        , np.uint32          ),
    ("sub_hdr_size"      , np.uint32          ),
    ("bitmap_blocks"     , np.uint32          ),
])

PageDescriptor = np.dtype([
    ("offset"     , np.uint64 ),
    ("size"       , np.uint32 ),
    ("flags"      , np.uint32 ),
    ("page_flags" , np.uint64 ),
])

class Compress(Enum):
    DUMP_DH_COMPRESSED_NONE   = 0x0
    DUMP_DH_COMPRESSED_ZLIB   = 0x1
    DUMP_DH_COMPRESSED_LZO    = 0x2
    DUMP_DH_COMPRESSED_SNAPPY = 0x4 


verbose = ('-v' in sys.argv)

# vprint for verbose logging
def vprint(*args):
    if (verbose): print(*args)

print('This is KdumpUncompress V1.0')
if len(sys.argv) <= 2:
    print('run \'kdumpuncompress.py -h\' for help')
    print('ERROR[kdumpuncompress]: missing arguments', file=sys.stderr)
    raise SystemExit(1)

infile = sys.argv[1]
outfile = sys.argv[2]
vprint('python version is', platform.python_version())

# read data
ddh = np.fromfile(infile, dtype=DiskDumpHeader64, count=1)[0]
do_swap = ((sys.byteorder == 'big') ^ (ddh['machine'].decode() == 's390x'))
#do_swap = ("-s" in sys.argv)
if do_swap: ddh = ddh.newbyteorder()

#print(ddh['signature'])
#print(ddh['header_version'])
#print(ddh['block_size'])
#print(type(ddh))
#print(dir(ddh))
#print(hexdump(ddh))
vprint(ddh)


compr = {1:'ZLIB', 2:'LZO', 3:'SNAPPY'}

if ddh['signature'] != b'KDUMP   ':
    raise SystemExit(f"file '{infile}' is not a kdump")
print('kdump version is', ddh['header_version'])
print(f"dumping system/machine is {ddh['sysname'].decode()}/{ddh['machine'].decode()}")
vprint('status is', ddh['status'])
if ddh['status']:
    pcompr = compr[ddh['status']]
    print(f"dump is {pcompr} compressed")
else:
    raise SystemExit('dump is not compressed. Nothing to do.')
pagesize = ddh['block_size']
print("dump pagesize is", pagesize)
print("dump subheader block size is", ddh['sub_hdr_size'])
print("dump bitmap block size is", ddh['bitmap_blocks'])
headersize = pagesize * (1 + ddh['sub_hdr_size'] + ddh['bitmap_blocks'])
pdstart = headersize
print(f"dump page descriptor starts at 0x{pdstart:06x}")
pstartzero = np.fromfile(infile, dtype=np.uint64, offset=headersize, count=1)[0]
if do_swap: pstartzero = pstartzero.newbyteorder()
print(f"dump pages start at 0x{pstartzero:08x}");
headersize = pstartzero
vprint(f"header ends at 0x{headersize:x}")
pstart = pstartzero + pagesize
with open(infile, 'rb') as fpin:
    chunk = fpin.read(pstart)
    with open(outfile, 'wb') as fpout:
        fpout.write(chunk)
        fpout.close()
with open(outfile, "a+b") as fp_out, open(outfile, "r+b") as fp_pd: 
#if True:
    paddr = 0
    n_poff = pstartzero + pagesize  # next page offset for output dump
    npages, zpages, cpages, rpages, pfpages  = [0, 0, 0, 0, 0]
    print("print progress any 1k pages with '#'...")
    while True:
        # read  page descriptor
        pd = np.fromfile(infile, dtype=PageDescriptor, offset=pdstart, count=1)[0]
        if do_swap: pd = pd.newbyteorder()
        npages += 1
        #print(pd)
        vprint([hex(x) for x in pd])
        #print(pd.nbytes)
        poff = pd['offset']
        psize = pd['size']
        pflags = pd['flags']
        sflags = pd['page_flags']
        #???memcpy(hdrbuf, php, sizeof(PageDescriptor));
        if not npages % 1024: print("#", end=''); sys.stdout.flush() # print page progress
        if poff == pstartzero:
            zpages += 1
            if verbose: print("z", end=''); sys.stdout.flush()
            pdstart += pd.nbytes 
            paddr += pagesize
            continue
        # flags DUMP_DH_COMPRESSED_ZLIB/LZO/SNAPPY, 0 is /NONE, raw page */
        if pflags:
            cpages += 1
        else: 
            rpages += 1
        #if (verbose) print("\n%6d  0x%08llx  0x%08llx  0x%04lx/%4ld      0x%04lx    0x%llx\n" % npages, paddr, poff, psize, psize, pflags, sflags)
        vprint('#', npages, paddr, poff, psize, psize, pflags, sflags)
        if sflags: pfpages += 1
        if not poff:
          print("\nend of pagedescriptor table\n")
          break
        #php = np.fromfile(infile, dtype='B4096', offset=pstart, count=1)[0]
        cdata = np.fromfile(infile, dtype='B', offset=pstart, count=psize)
        if not len(cdata):
            print(f"\nWARNING: input dump has been truncated at or after offset 0x{pstart:08x}\n")
            break
        vprint('cdata', len(cdata), ':')
        if verbose: hexdump(cdata[:32])
        if not pflags: rdata = cdata  # raw page
        if pflags:
            if pflags == Compress.DUMP_DH_COMPRESSED_LZO.value:
                try:
                    rdata = lzo.decompress(cdata, False, pagesize)
                    outsize = pagesize
                    if len(rdata) != pagesize:
                        print("lzo uncompress error!\n")
                        rdata = bytearray(pagesize)
                        break
                except lzo.error:
                    print("Unexpected error:", sys.exc_info())
                    rdata = bytearray(pagesize)
                    break

            elif pflags == Compress.DUMP_DH_COMPRESSED_ZLIB.value:
                try:
                    rdata = zlib.decompress(cdata)
                    outsize = pagesize
                    if len(rdata) != pagesize:
                        print("zlib uncompress error!\n")
                        rdata = bytearray(pagesize)
                        break
                except zlib.error:
                    print("Unexpected error:", sys.exc_info())
                    rdata = bytearray(pagesize)
                    break
            else:
                raise SystemExit(f'unknown compression flag: {pflags}')

            vprint('rdata', len(rdata), ':')
            if verbose: hexdump(rdata[:32])
            pd['offset'] = n_poff
            pd['size'] = outsize
            pd['flags'] = Compress.DUMP_DH_COMPRESSED_NONE.value
            #pd['page_flags'] = 0
            fp_pd.seek(pdstart)
            pd.tofile(fp_pd)
            vprint(f"        fwrite at 0x{pdstart:08x}: {pd.nbytes}\n")

        else:  # cdata page uncompressed
            outsize = psize
        fp_out.write(rdata)
        vprint(f"        fwrite at 0x{n_poff:08x}: {outsize}\n")
        n_poff += outsize
        pstart += psize
        pdstart += pd.nbytes
        paddr += pagesize
    print(f"page descriptor entries: {npages}")
    print(f"{zpages} zeropages, {rpages} raw, {cpages} decompressed, {pfpages} with pageflags\n")
    # set output dump status
    ddh['status'] = Compress.DUMP_DH_COMPRESSED_NONE.value
    fp_pd.seek(0)
    ddh.tofile(fp_pd)
print("kdumpuncompress done.")

