import pwn
from keystone import *
pwn.context(os='linux',arch='thumb')
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
import re
import struct

def _asm(text, vmabase):
  code = pwn.asm(text,vma=vmabase)
  return code

def ks_asm(text, vmabase):
  encoding, count = ks.asm(text, vmabase)
  for i, s in enumerate(encoding):
    encoding[i] = struct.pack('<B',s)

  code = "".join(encoding)
  #print "KSASSM:%s"%code
  return code