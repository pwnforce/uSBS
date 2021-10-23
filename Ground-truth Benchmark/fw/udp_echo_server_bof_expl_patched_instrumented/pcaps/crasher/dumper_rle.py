#
# Dumps Ethernet frames from a folder of pcapng files for use with AFL
# takes any packet going to dst_mac, or sent as a broadcast.
# Frames are encoded with an RLE style format -- a little-endian length followed by
# the data, followed by 0xdeadbeef
# When we load the data later after AFL gets to it,
# if the frame doesn't end with 0xdeadbeef, afl mutated the wrong thing, tell it not to!

import dpkt
import os
import sys
import struct

dst_mac = b"\x02\x00\x00\x00\x00\x00"#.replace(":", "").encode()#.decode('hex')
all_fs = b'\xff\xff\xff\xff\xff\xff'
marker = b'\xbe\xef\xfa\xce'


MTU_SIZE = 1520

for fn in os.listdir("."):
    if fn.endswith("pcap"):
        outfn = fn + ".input"
        outf = open(outfn, 'wb')
        with open(fn, 'rb') as f:
            r = dpkt.pcap.Reader(f)
            for ts, buf in r:

                eth = dpkt.ethernet.Ethernet(buf)
                if (eth.dst != dst_mac and eth.dst != all_fs) or eth.src == dst_mac:
                    print("Nope", eth.dst, dst_mac, eth.dst, all_fs, eth.src, dst_mac)
                else:
                    print("YES", eth.dst, dst_mac, eth.dst, all_fs, eth.src, dst_mac)
                    # filter
                    buf = buf + marker
                    outf.write(buf)

        outf.close()
    print("DONE")

