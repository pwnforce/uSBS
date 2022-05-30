import capstone

class USBSDisassembler():
  def __init__(self,arch,context):
    if arch == 'arm':
      self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
      self.context=context
    else:
      raise NotImplementedError( 'Architecture %s is not supported'%arch )
    self.md.detail = True
    
  def disasm(self,bytes,base):
    instoff=0  
    while instoff < len(bytes):
      try:
        insts = self.md.disasm(bytes[instoff:instoff+4],base+instoff)
        ins = insts.next() 
        if ins.address in self.context.not_trans:
          retval=[]
          retval.append(base+instoff)
          retval.append(bytes[instoff:instoff+4])
          instoff+=4
          yield retval
          continue
        if ins.address in self.context.not_trans_tbb:
          retval=[]
          retval.append(base+instoff)
          retval.append(bytes[instoff:instoff+4])
          retval.append("TBB")
          instoff+=4
          yield retval
          continue
        instoff+=len(ins.bytes)
        yield ins
      except StopIteration: 
        instoff+=4
        retval=[]
        retval.append(base+instoff-4)
        retval.append(bytes[instoff-4:instoff])
        yield retval