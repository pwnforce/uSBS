#!/usr/bin/python

import sys
import time
from elftools.elf.elffile import ELFFile
from usbs import Rewriter
from usbs_assembler import _asm,ks_asm


def indirect_branch(inst, regnum):
  temp = '''
    str r2, [sp, #-96]
    mov.w r2, #0x10
    push r2
    ldr r2, [sp, #-96] 
    svc 255 
  '''
  return _asm(temp, 0x08100000 )

def func_beginning(inst, regnum):
  temp = '''
    str r2, [sp, #-96]
    push lr 
    mov.w r2, #0x20 
    push r2 
    push r2 
    ldr r2, [sp, #-96] 
    svc 255 
  '''
  return _asm( temp%(regnum*4), 0x08100000 )

def ret(inst, regnum):
  temp = '''
    str r2, [sp, #-96] 
    mov.w r2, #0x21 
    push r2 
    push r2 
    ldr r2, [sp, #-96] 
    svc 255 
  '''
  return _asm( temp%(regnum*4), 0x08100000 )


if __name__ == '__main__':
  

  if len(sys.argv) == 2:
    start = time.time()
    f = open(sys.argv[1])
    e = ELFFile(f)
    entry_point = e.header.e_entry
    f.close()
    rewriter = Rewriter()
    rewriter.set_indirect_branch(indirect_branch)
    rewriter.set_func_beginning(func_beginning)
    rewriter.set_before_ret(ret)
    rewriter.rewrite(sys.argv[1],'arm')
    end = time.time()
    print("Processing Time:")
    print(end - start)
  else:
    print("Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0])
