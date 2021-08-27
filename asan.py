#!/usr/bin/python

import sys
import time
from elftools.elf.elffile import ELFFile
from usbs import Rewriter
from usbs_assembler import _asm,ks_asm


def push_poison(inst):
  calltemp = '''
    str r2, [sp, #-96]
    str r3, [sp, #-160]
    mov.w r2, #0xffffffff
    mov.w r3, #8196
    neg r3, r3
    str r2, [sp, r3]
    ldr r3, [sp, #-160]
    ldr r2, [sp, #-96]
  '''
  return _asm( calltemp, 0x08100000 )

def push_it_poison(inst, regnum, it_cond):
  calltemp = '''
    itttt %s
    str r2, [sp, #-128]
    str r3, [sp, #-160]
    ldr r2, =0xffffffff
    ldr r3, =8192
    itttt %s
    neg r3, r3
    add r3, %s
    str r2, [sp, r3]
    ldr r3, [sp, #-160]
    itt %s
    ldr r2, [sp, #-128]
  '''
  return _asm( calltemp%(it_cond, it_cond, regnum*4, it_cond), 0x08100000 )


def mem_poison(inst, target, offset1, offset2, stackaddr, src):
  stack_low_addr  = "0x" + str(hex(stackaddr))[6:10]
  stack_high_addr = "0x" + str(hex(stackaddr))[2:6]
  peripheral_low_addr = "0x0000"
  peripheral_high_addr = "0x4000"
  registers= ["r0", "r1", "r2", "r3", "r4", "r5", "r6"]
  free_register1 = None
  free_register2 = None
  for r in registers:
    #print r
    if r != target and r != offset1 and r != src:
      free_register1 = r
      registers.remove (free_register1)
      break
  for r in registers:
    #print "----"
    #print r
    if r != target and r != offset1 and r != src:
      free_register2 = r
      break

  


  memtemp1 = '''
    str %s, [sp, #-128]
    mrs %s, apsr
    str %s, [sp, #-96]
    movw %s,%s
    movt %s,%s
    cmp %s,%s
    blt label
    movw %s,%s
    movt %s,%s
    cmp %s,%s
    bge label
    sub %s, %s, #8192
    str %s, [%s]
    label:
    ldr %s, [sp, #-96]
    msr apsr, %s
    ldr %s, [sp,#-128]
  '''

  memtemp2 = '''
    str %s, [sp, #-128]
    str %s, [sp, #-160]
    mrs %s, apsr
    str %s, [sp, #-96]
    add %s, %s, %s
    movw %s, %s
    movt %s, %s
    cmp %s, %s
    blt label
    movw %s,%s
    movt %s,%s
    cmp %s, %s
    bge label
    sub %s, #8192
    str %s, [%s]
    label:
    ldr %s, [sp, #-96]
    msr apsr, %s
    ldr %s, [sp, #-160]
    ldr %s, [sp, #-128]
  '''

  memtemp3 = '''
    str %s, [sp, #-128]
    str %s, [sp, #-160]
    mrs %s, apsr
    str %s, [sp, #-96]
    add %s, %s, %s, %s
    movw %s, %s
    movt %s, %s
    cmp %s, %s
    blt label
    movw %s,%s
    movt %s,%s
    cmp %s, %s
    bge label
    sub %s, #8192
    str %s, [%s]
    label:
    ldr %s, [sp, #-96]
    msr apsr, %s
    ldr %s, [sp, #-160]
    ldr %s, [sp, #-128]
  '''

 

  if offset1 == None:
    return ks_asm( memtemp1%(free_register1,free_register1,free_register1, free_register1, stack_low_addr, free_register1, stack_high_addr, target, free_register1, free_register1, peripheral_low_addr, 
  free_register1, peripheral_high_addr, target, free_register1,  free_register1, target, src, free_register1, free_register1, free_register1, free_register1), 0x08100000 )
  elif offset2 == None:
    return ks_asm( memtemp2%(free_register1, free_register2, free_register1, free_register1, free_register2,  target, offset1, free_register1, stack_low_addr, free_register1, stack_high_addr,  free_register2, free_register1, free_register1, peripheral_low_addr, 
  free_register1, peripheral_high_addr, free_register2, free_register1, free_register2, src, free_register2, free_register1, free_register1, free_register2, free_register1), 0x08100000 )
  elif "lsl" in offset2:
    return ks_asm( memtemp3%(free_register1, free_register2,free_register1,free_register1, free_register2, target, offset1, offset2, free_register1, stack_low_addr, free_register1, stack_high_addr,  free_register2, free_register1, free_register1, peripheral_low_addr, 
  free_register1, peripheral_high_addr, free_register2, free_register1, free_register2, src, free_register2, free_register1, free_register1, free_register2, free_register1), 0x08100000 )
  else:
    return ks_asm( memtemp4%(free_register1, free_register2, free_register2, target, offset1, free_register2, offset2, free_register1, stack_low_addr, free_register1, stack_high_addr,  free_register2, free_register1, free_register1, peripheral_low_addr, 
  free_register1, peripheral_high_addr, free_register2, free_register1, free_register2, src, free_register2, free_register2, free_register1), 0x08100000 )

def mem_poison2(inst, target, offset, stackaddr, src1, src2):
  stack_low_addr  = "0x" + str(hex(stackaddr))[6:10]
  stack_high_addr = "0x" + str(hex(stackaddr))[2:6]
  peripheral_low_addr = "0x0000"
  peripheral_high_addr = "0x4000"
  registers= ["r0", "r1", "r2", "r3", "r4", "r5", "r6"]
  free_register1 = None
  free_register2 = None
  for r in registers:
    if r != target and r != offset and r != src1 and r != src2:
      free_register1 = r
      registers.remove (free_register1)
      break
  for r in registers:
    if r != target and r != offset and r != src1 and r != src2:
      free_register2 = r
      break

  memtemp1 = '''
    str %s, [sp, #-128]
    mrs %s, apsr
    str %s, [sp, #-96]
    movw %s,%s
    movt %s,%s
    cmp %s,%s
    blt label
    movw %s,%s
    movt %s,%s
    cmp %s,%s
    bge label
    sub %s, %s, #8192
    strd %s, %s, [%s]
    label:
    ldr %s, [sp, #-96]
    msr apsr, %s
    ldr %s, [sp,#-128]
  '''

  memtemp2 = '''
    str %s, [sp, #-128]
    str %s, [sp, #-160]
    mrs %s, apsr
    str %s, [sp, #-96]
    add %s, %s, %s
    movw %s, %s
    movt %s, %s
    cmp %s, %s
    blt label
    movw %s,%s
    movt %s,%s
    cmp %s, %s
    bge label
    sub %s, #8192
    strd %s, %s, [%s]
    label:
    ldr %s, [sp, #-96]
    msr apsr, %s
    ldr %s, [sp, #-160]
    ldr %s, [sp, #-128]
  '''
  if offset == None:
    return ks_asm( memtemp1%(free_register1,free_register1, free_register1, free_register1, stack_low_addr, free_register1, stack_high_addr, target, free_register1, free_register1, peripheral_low_addr, 
    free_register1, peripheral_high_addr, target, free_register1,  free_register1, target, src1, src2, free_register1,free_register1,free_register1, free_register1), 0x08100000 )
  else:
    return ks_asm( memtemp2%(free_register1, free_register2, free_register1, free_register1, free_register2,  target, offset, free_register1, stack_low_addr, free_register1, stack_high_addr,  free_register2, free_register1, free_register1, peripheral_low_addr, 
    free_register1, peripheral_high_addr, free_register2, free_register1, free_register2, src1, src2, free_register2,free_register1,free_register1, free_register2, free_register1), 0x08100000 )



def ret_poison(inst, regnum):
  rettemp = '''
    str r2, [sp, #-96]
    str r3, [sp, #-160]
    str r4, [sp, #-128]
    mov.w r2, #0xffffffff
    mov.w r3, #8192
    neg r3, r3
    add r3, %s
    ldr r4, [sp, r3]
    cmp r4, r2
    label:
    bne label
    mov.w r2, #0x00000000
    str r2, [sp, r3]
    ldr r4, [sp, #-128]
    ldr r3, [sp, #-160]
    ldr r2, [sp, #-96]
  '''
  return _asm( rettemp%(regnum*4), 0x08100000 )


def ret_bxlr_poison(inst, regnum):
  rettemp = '''
    str r2, [sp, #-96]
    str r3, [sp, #-160]
    mov.w r3, #8192
    neg r3, r3
    add r3, %s
    mov.w r2, #0x00000000
    str r2, [sp, r3]
    ldr r3, [sp, #-160]
    ldr r2, [sp, #-96]
  '''
  return _asm( rettemp%(regnum*4), 0x08100000 )

def iprintf_ins(inst):
  rettemp = '''
    str r3, [sp, #-160]
    sub r3, sp, #352
    str r0, [r3]
    add r0, pc, #16
    bl  0x8011fb4
    sub r3, sp, #352
    ldr r0, [r3]
    add r3, pc, #7
    bx r3
  '''
  return _asm( rettemp, 0x081013b0 )


if __name__ == '__main__':
  

  if len(sys.argv) == 2:
    start = time.time()
    f = open(sys.argv[1])
    e = ELFFile(f)
    entry_point = e.header.e_entry
    f.close()
    rewriter = Rewriter()
    rewriter.set_before_push(push_poison)
    rewriter.set_before_push_it(push_it_poison)
    rewriter.set_before_str(mem_poison)
    rewriter.set_before_strd(mem_poison2)
    rewriter.set_before_ret(ret_poison)
    rewriter.set_before_ret_bxlr(ret_bxlr_poison)
    rewriter.set_before_malloc(iprintf_ins)
    rewriter.rewrite(sys.argv[1],'arm')
    end = time.time()
    print "Processing Time:"
    print(end - start)
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0]
