from usbs_assembler import _asm,ks_asm
from capstone.arm import (ARM_CC_EQ, ARM_CC_NE, ARM_CC_HS, ARM_CC_LO,
        ARM_CC_MI, ARM_CC_PL, ARM_CC_VS, ARM_CC_VC, ARM_CC_HI,
        ARM_CC_LS, ARM_CC_GE, ARM_CC_LT, ARM_CC_GT, ARM_CC_LE, ARM_CC_AL,
        ARM_INS_EOR, ARM_INS_ADD, ARM_INS_ORR, ARM_INS_AND, ARM_INS_MOV,
        ARM_INS_CMP, ARM_INS_SUB, ARM_INS_LDR, ARM_INS_B, ARM_INS_BLX,
        ARM_INS_BL, ARM_INS_BX, ARM_REG_LR, ARM_OP_REG, ARM_REG_PC, ARM_INS_POP, ARM_OP_MEM,ARM_OP_IMM)
import struct
import re
from keystone import *
import binascii

class USBSTranslator():

  def __init__(self,before_push,before_push_it,before_str,before_strd,before_ret,before_ret_bxlr,before_malloc,context):
    self.ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    self.before_push = before_push
    self.before_push_it = before_push_it
    self.before_str = before_str
    self.before_strd = before_strd
    self.before_ret = before_ret
    self.before_ret_bxlr = before_ret_bxlr
    self.before_malloc = before_malloc
    self.it_mask = ""
    self.it_cond = ""
    self.context = context
    self.lastpoisonedfunc = None
    
  def translate_one(self,ins,mapping):
    #print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))s

    #if len(self.it_mask) > 0:
    #  print "It Mask:%s"%self.it_mask
    #  if self.it_mask[0] == 't':
    #    it_insert = self.it_bytes[self.it_cond]
    #  if self.it_mask[0] == 'e':
    #    it_insert = self.it_bytes[self.opposite[self.it_cond]]
    #  self.it_mask = self.it_mask[1:]

    match = re.search("^(b|bl|blx|bx)(|eq|ne|gt|lt|ge|le|cs|hs|cc|lo|mi|pl|al|nv|vs|vc|hi|ls)(|.w)$", ins.mnemonic)
    if match:
      return self.translate_uncond(ins,mapping)
    elif ins.mnemonic.startswith('it'):  #there is sth wrong with handling that in toggle app at address 8000c3e (ittt ne) in HAL_RCC_ClockConfig function.
      return self.translate_it(ins)
    elif "ldr" in ins.mnemonic: 
      return self.translate_ldr(ins,mapping)
    elif ins.mnemonic in ['cbz','cbnz']:
      return self.translate_cbz(ins,mapping)  

    #elif ins.mnemonic.startswith('push'): # baraye halate asan comment in khat va khat badi ra bardar (baraye asan bayad push, pop, str, va bxlr dar func translate_uncond ra uncomment kard)
    #  return self.translate_push(ins,mapping)
    #elif ins.mnemonic.startswith('pop'): # baraye halate asan comment in khat va khat badi ra bardar 
    #  return self.translate_pop(ins,mapping)
    #elif ins.mnemonic.startswith('str'): # baraye halate asan comment in khat va khat badi ra bardar 
    #  return self.translate_str(ins,mapping)
   
      
    elif ins.mnemonic.startswith('tbb'): #you should manually adjust the tbb by yourself with the tbb tool.
      print('Found tbb instruction at 0x%x'%ins.address)
     # return self.translate_tbb(ins,mapping)
    elif ins.mnemonic.startswith('tbh'): #you should manually adjust the tbh by yourself with the tbh tool.
      print('Found tbh instruction at 0x%x'%ins.address)
     # return self.translate_tbh(ins,mapping)
    



    #elif ins.address == 0x8000f9e: #temporaryyyyy
    #  inserted= None #temporaryyyyy
     # code= b'' #temporaryyyyy
     # inserted =  self.before_malloc(ins)   + "\x41\x41\x41\x41\x5d\xf8\xa0\x3c" #temporaryyyyy
     # return inserted + str(ins.bytes) #temporaryyyyy




    else: #Any other instruction
      if len(self.it_mask) > 0: #this is for dont instrumenting in IT block
        self.it_mask = self.it_mask[1:]
      #if(ins.address not in not_insert):
      #  inserted = self.before_inst_callback(ins)
      #if inserted is not None:
      #  return inserted + str(ins.bytes)
      return None #No translation needs to be done



  def translate_it(self,ins):
    code = b''
    self.it_mask = ins.mnemonic.replace("i","")
    self.it_cond = ins.op_str
    return None





  def get_current_func(self,ins):
    prevfunc = None
    currfunc = None
    islast=True
    for k in sorted(self.context.flist.keys()):
      if ins.address < k-1 :
        islast=False
        currfunc = prevfunc
        break
      prevfunc = self.context.flist[k]["name"]
    if islast:
      currfunc = prevfunc
    return currfunc



  def translate_str(self,ins,mapping):
    #print "1str"
    if len(self.it_mask) > 0: #this is for dont instrumenting in IT block
      #print "2str"
      self.it_mask = self.it_mask[1:]
      return None
    #print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
    inserted= None
    code= b''
    operands = ins.op_str.split(", ")
    opcnt = len(operands)
 
    for k in range(opcnt):
      if "]" in operands[k]:
        lastoperand = k
      operands[k]=operands[k].replace("[","")
      operands[k]=operands[k].replace("]","")
      operands[k]=operands[k].replace("!","")
    operands = operands[:lastoperand+1]
    opcnt = len(operands)
    #print operands
    #print opcnt
    #if (ins.address < 0x8000b90 or ins.address > 0x8000c2c) and ins.address != 0x800a06e: #temporaryyyyy
    #  return str(ins.bytes) #temporaryyyyy

    if ins.mnemonic != "strd":
      if opcnt == 2:
        inserted =  self.before_str(ins, operands [1], None, None, self.context.stackaddr, operands [0])  
        #print "inserted%s"%inserted
        return inserted + str(ins.bytes)
      elif opcnt == 3:
        inserted = self.before_str(ins, operands [1], operands [2],None, self.context.stackaddr, operands [0]) 
        #print "inserted%s"%inserted
        return inserted + str(ins.bytes)
      elif opcnt == 4:
        inserted =  self.before_str(ins, operands [1], operands [2], operands[3], self.context.stackaddr, operands [0])  
        #print "inserted%s"%inserted
        return inserted + str(ins.bytes)
    else:
      if opcnt == 3:
        inserted =  self.before_strd(ins, operands [2], None, self.context.stackaddr, operands [0], operands [1])  
        #print "inserted%s"%inserted
        return inserted + str(ins.bytes)
      elif opcnt == 4:
        inserted =  self.before_strd(ins, operands [2], operands [3], self.context.stackaddr, operands [0], operands [1])
        #print "inserted%s"%inserted
        return inserted + str(ins.bytes)


  

 

  def translate_pop(self,ins,mapping):
    if len(self.it_mask) > 0: #this is for dont instrumenting in IT block
      #print "2str"
      self.it_mask = self.it_mask[1:]
      return None
    inserted= None
    code= b''
    opcnt = len(ins.operands)
    operator=ins.op_str
    #if ins.address < 0x8000b90 or ins.address > 0x8000c2c: #temporaryyyyy
    #  return str(ins.bytes) #temporaryyyyy
    if "pc" in operator:
      currfunc = self.get_current_func(ins)
      if currfunc == self.lastpoisonedfunc:
        #print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
        #print "pop %s"%opcnt
        inserted = "\x4d\xf8\x80\x2c\xef\xf3\x00\x82" + self.before_ret(ins, opcnt-1)   + "\x82\xf3\x00\x88\x5d\xf8\x80\x2c"
        return inserted + str(ins.bytes)
    return None
  
  def translate_bxlr(self,ins,mapping):
    if len(self.it_mask) > 0: #this is for dont instrumenting in IT block
      #print "2str"
      self.it_mask = self.it_mask[1:]
      return None
    inserted= None
    code= b'' 
    currfunc = self.get_current_func(ins)
    #if currfunc == self.lastpoisonedfunc:
     # inserted = "\x4d\xf8\x40\x2c\xef\xf3\x00\x82" + self.before_ret(ins, -1) + "\x82\xf3\x00\x88\x5d\xf8\x40\x2c"
    #  return inserted + str(ins.bytes) 
    #return str(ins.bytes) #temporaryyyyy
    if currfunc == self.lastpoisonedfunc:
      inserted = "\x4d\xf8\x80\x2c\xef\xf3\x00\x82" + self.before_ret_bxlr(ins, -1) + "\x82\xf3\x00\x88\x5d\xf8\x80\x2c"
      return inserted + str(ins.bytes)   
    return None

  def translate_push(self,ins,mapping): 
    if len(self.it_mask) > 0: #this is for dont instrumenting in IT block
      #print "2str"
      self.it_mask = self.it_mask[1:]
      return None

    # The following temp is an Example for stack based buffer overflow :-)
    #temp = '''         
    #str r0, [sp, #-64]
    #add r0, sp, #12
    #sub r0, #8192
    #str r2, [r0]
    #ldr r0, [sp, #-64]
    #str r2, [sp, #12]
    #'''
    inserted = None
    code= b''
    operator = ins.op_str
    #if ins.address < 0x8000b90 or ins.address > 0x8000c2c: #temporaryyyyy this was for a firmware that I wanted to only sanitize one function not all instructions. 
    #  return str(ins.bytes) #temporaryyyyy
    if "lr" in operator:
      currfunc = self.get_current_func(ins)
      self.lastpoisonedfunc = currfunc
      inserted = "\x4d\xf8\x80\x2c\xef\xf3\x00\x82" + self.before_push(ins) + "\x82\xf3\x00\x88\x5d\xf8\x80\x2c"
      #if ins.address == 0x8000e5c:     #it is just for writing on LR in function __libc_init_array in toggle app (it should be uncommented when you want to run the stack buffer overflow example which is defined in temp at the beginning of func.)
      #  return inserted + str(ins.bytes) + _asm( temp, 0x8001000 )
      return inserted + str(ins.bytes)
    return None

  
  def translate_tbb (self,ins,mapping):
    #print "this is a tbb address: %s"%hex(ins.address)
    operator=ins.op_str
    if "[pc," in operator:
      tbb_addr =  ins.address + 4
      if mapping is not None and ins.address in mapping:
        tbb_addrnew = self.context.newbase + mapping[ins.address] + 4
        #print "this is a tbb pc table address: %s"% hex(tbb_addr)
        #print "this is a new tbb pc table address: %s"% hex(tbb_addrnew)
      #self.context.not_trans_tbb.append(tbb_addr)
      #self.context.not_trans_tbb.append(tbb_addr+2)
  
  
  def translate_tbh (self,ins,mapping):
    #print "this is a tbh address: %s"%hex(ins.address)
    operator=ins.op_str
    if "[pc," in operator:
      tbh_addr =  ins.address + 4
      if mapping is not None and ins.address in mapping:
        tbh_addrnew = self.context.newbase + mapping[ins.address] + 4
        #print "this is a tbh pc table address: %s"%hex(tbh_addr)
        #print "this is a new tbh pc table address: %s"%hex(tbh_addrnew)    

    
  def translate_ldr(self,ins,mapping):


    #if ins.address == 0x8000bb0: #temporaryyyyy
    #  print "we are exiting BOF!"
    #  inserted= None
    #  code= b'' 
    #  currfunc = self.get_current_func(ins)
    #  if currfunc == self.lastpoisonedfunc:
     #   inserted = "\x4d\xf8\x80\x2c\xef\xf3\x00\x82" + self.before_ret(ins, 0)  + "\x82\xf3\x00\x88\x5d\xf8\x80\x2c"
     #   return inserted + str(ins.bytes)   
    #  return None
      
    it_status=False
    if len(self.it_mask) > 0: #this is for dont instrumenting in IT block
      self.it_mask = self.it_mask[1:]
      it_status = True
    code= b''
    newtarget = self.context.newbase +4
    newtarget_low_addr  = "0x" + str(hex(newtarget))[-4:]
    newtarget_high_addr = str(hex(newtarget))[:-4]
    operator=ins.op_str
    op1 = ins.operands[0]
    reg=  ins.reg_name(op1.reg)
    template = ''
    #print reg
    template = '''
      movw %s, %s
      movt %s, %s
      ldr.w  %s, [%s]
      '''

    if "[pc," in operator:
      match = re.search('#(0x)*([0-9a-f]+)', operator)
      if match:
        targetadd = ins.address + int(str(match.group(2)),16) + 4
        if (targetadd%0x4 != 0):
          targetadd -= ( 0x4 - targetadd%0x4 )
        #print hex(targetadd)
        self.context.not_trans.append(targetadd)
        self.context.not_trans.append(targetadd+2)
        if mapping is not None and targetadd in mapping:
          newtarget = self.context.newbase + mapping[targetadd]
          newtarget_low_addr  = "0x" + str(hex(newtarget))[-4:]
          newtarget_high_addr = str(hex(newtarget))[:-4]
          vmabase = self.context.newbase + mapping[ins.address] + len(code)

          off = newtarget - vmabase - 4
          if (vmabase%0x4 !=0):
            off+=2
          #print "-------"
          #print operator
          #print hex(ins.address)
         # print hex(targetadd)
          #print hex(vmabase)
          #print hex(newtarget)
         # print hex(mapping[ins.address])
          #print hex(off)
          #print "-------"
          if "0x" in operator:
            operator = operator.replace("0x"+str(match.group(2)), hex(off))
          if "0x" not in operator:
            operator = operator.replace("#"+str(match.group(2)), "#"+hex(off))
         # print "newoperatpr:%s"%(operator)
          #if ".w" not in ins.mnemonic:
            #print len(_asm( '%s.w %s'%(ins.mnemonic,operator),self.context.newbase))
          #  print  '%s.w %s'%(ins.mnemonic,operator)
          #  print len(_asm( '%s.w %s'%(ins.mnemonic,operator),vmabase  ))
          #  print '%s.w %s'%(ins.mnemonic,operator)
          #  code += _asm( '%s.w %s'%(ins.mnemonic,operator),vmabase  )  
          #  return code
          if reg != "sp" and not it_status:
            #print template%(reg,newtarget_low_addr, reg, newtarget_high_addr, reg, reg)
            code += _asm( template%(reg,newtarget_low_addr, reg, newtarget_high_addr, reg, reg),vmabase  ) 
            return code
          else: 
            if ".w" not in ins.mnemonic:
              code += _asm( '%s.w %s'%(ins.mnemonic,operator),vmabase  )  
              return code
            else:
              code += _asm( '%s %s'%(ins.mnemonic,operator),vmabase  )  
              return code  

        #if ".w" not in ins.mnemonic:  
        #  code += _asm( '%s.w %s'%(ins.mnemonic,operator),self.context.newbase  ) 
        #  return code
        if reg != "sp" and not it_status:
          code += _asm( template%(reg,newtarget_low_addr, reg, newtarget_high_addr, reg, reg),self.context.newbase  )
          return code
        else: 
          if ".w" not in ins.mnemonic:
            code += _asm( '%s.w %s'%(ins.mnemonic,operator),self.context.newbase  )  
            return code
          else:
            code += _asm( '%s %s'%(ins.mnemonic,operator),self.context.newbase  )  
            return code    
    #if (len(code) > 0):      
    #  code += str(ins.bytes)   
    #  return code 
    return None
  
  def translate_cbz(self,ins,mapping):
    inserted= None
    op1 = ins.operands[0]
    reg=  ins.reg_name(op1.reg)
    op2 = ins.operands[1]
    target=op2.imm
    template=''
    #if(ins.address not in not_insert):
    #  inserted = self.before_inst_callback(ins)
    #if inserted is not None:
     # code += inserted
    if ins.mnemonic == "cbz":
      template = '''
      cbnz %s, label
      b.w %s
      label:
      '''
    elif ins.mnemonic == "cbnz":
      template = '''
      cbz %s, label
      b.w %s
      label:
      '''

    
    newtarget = self.context.newbase + 4
    if mapping is not None and target in mapping:
      newtarget=self.context.newbase+ mapping[target]
      vmabase=self.context.newbase+mapping[ins.address]
      newtarget = hex(newtarget)
      #print "target: %s"%hex(target)
      #print "newtarget: %s"%newtarget
      #print ins.mnemonic
      #print vmabase
      
      encoding, count = self.ks.asm(template%(reg,newtarget), vmabase)
      for i, s in enumerate(encoding):
        encoding[i] = struct.pack('<B',s)
      code = "".join(encoding)
     # print code 
     # print "coount%s"%count
      return code
    encoding, count = self.ks.asm(template%(reg,newtarget), self.context.newbase) 
    for i, s in enumerate(encoding):
      encoding[i] = struct.pack('<B',s)
    code = "".join(encoding)
    #print code 
    #print "coount%s"%count
    return code

  def translate_uncond(self,ins,mapping):
    code= b''
    op = ins.operands[0] #Get operand
    if op.type == ARM_OP_REG: # e.g. call eax or jmp ebx
      #return str(ins.bytes) #temporaryyyyy
      target = ins.reg_name(op.reg)
      if str(target) != 'lr':
        print('! Found an indirected jump to %s at %s'%(target, hex(ins.address)))

      #if (target=="lr"):   # baraye halate asan comment in khat va khat badi ra bardar 
      #  return self.translate_bxlr(ins, mapping)

      if (ins.mnemonic == "blx"):
        print('Instrumenting an indirected jump to %s at %s'%(target, hex(ins.address)))
        return self.get_indirect_uncond_code(ins,mapping,target)
      if (len(code) > 0):       
        code += str(ins.bytes)     
        return code 
      return None

    if len(self.it_mask) > 0: #this is for dont instrumenting in IT block
      self.it_mask = self.it_mask[1:]
    elif op.type == ARM_OP_IMM: # e.g. call 0xdeadbeef or jmp 0xcafebada
      target = op.imm
      #if(ins.address not in not_insert):
      #  inserted = self.before_inst_callback(ins)
      #if inserted is not None:
      #  code += inserted

      #print hex(ins.address)

      newtarget = self.context.newbase + 4
      if mapping is not None and target in mapping:
        newtarget=self.context.newbase+ mapping[target]
        vmabase=self.context.newbase+mapping[ins.address] + len (code)
        newtarget = hex(newtarget)
        
       # print "target: %s"%hex(target)
        #print "newtarget: %s"%newtarget
        #print ins.mnemonic
        #print vmabase
       # print "%s : (%s+%s) = %s"%(hex(vmabase),hex(mapping[target]),hex(self.context.newbase),newtarget)
       # print '%s %s'%(ins.mnemonic,newtarget)
        code += _asm( '%s %s'%(ins.mnemonic,newtarget),vmabase  )
        return code
        #print "new length: %s"%len(callback_code+patched)
      code += _asm( '%s %s'%(ins.mnemonic,newtarget),self.context.newbase)
      return code
      
    if (len(code) > 0):      
      code += str(ins.bytes)   
      return code 
    return None
  
  def get_indirect_uncond_code(self,ins,mapping,target):
   
    template = '''
    str r0, [sp, #-64]
    mov r0, %s
    bl #%s
    str r0, [sp,#-8]
    ldr r0, [sp,#-64]
    add lr, pc, #5
    ldr pc, [sp,#-8]
    ''' # we add 4 + 1 to the link register for the thumb bit
    # TODO: we should add the +1 depending if we're manipulating addresses referring to thumb or normal arm assembly. This is doable at instrumentation time.
 
    code = b''

    #inserted = self.before_inst_callback(ins)
    #if inserted is not None:
    #  code += inserted

    lookup_target = self.context.newbase
    if mapping is not None and ins.address in mapping:
      vmabase=self.context.newbase+mapping[ins.address] + len(code)
      print "lookup_target::%s"%(hex(lookup_target))
      code += _asm( template%(target,lookup_target) , vmabase)
      return code
    code += _asm( template%(target,lookup_target) , self.context.newbase)
    return code

