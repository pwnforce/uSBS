#!/usr/bin/python
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import capstone
import sys
import usbs_assembler
import usbs_writer
import json
import os
import re
from context import Context
from usbs_mapper import USBSMapper




class Rewriter(object):

  def __init__(self):
    self.context = Context()
  def set_before_push(self,func):
    self.context.before_push = func
  def set_before_push_it (self, func):
    self.context.before_push_it = func
  def set_before_str(self,func):
    self.context.before_str = func
  def set_before_strd(self,func):
    self.context.before_strd = func  
  def set_before_ret(self,func):
    self.context.before_ret = func
  def set_before_ret_bxlr (self, func):
    self.context.before_ret_bxlr = func
  def set_before_malloc (self, func):
    self.context.before_malloc = func

    

        
 

  def rewrite(self,fname,arch):
    offs = size = addr = 0
    with open(fname,'rb') as f:
      elffile = ELFFile(f)
      entry = elffile.header.e_entry #application entry point
      self.context.newbase = 0x08010000  #put 0x08100000 for eval board
      for section in elffile.iter_sections():
        if section.name == '.text':
          print "Found .text"
          offs = section.header.sh_offset
          size = section.header.sh_size
          addr = section.header.sh_addr
          self.context.oldbase = addr
          bytes=section.data()
          base=addr
          mapper = USBSMapper(arch,bytes,base,entry,self.context) 
          mapping = mapper.gen_mapping()
          newbytes = mapper.gen_newcode(mapping)
        
          with open('map.json','wb') as f:
            json.dump(mapping,f)
          with open('newbytes','wb') as f2:
            f2.write(newbytes)
          print base
          maptext = mapper.write_mapping(mapping,base,len(bytes))
          print "byte length:%x"%len(bytes)
          usbs_writer.rewrite(fname,fname+'-r','newbytes',self.context.newbase)
    
    
if __name__ == '__main__':
  import argparse
  parser = argparse.ArgumentParser(description='''Rewrite a binary so that the code is relocated.
Running this script from the terminal does not allow any instrumentation.
For that, use this as a library instead.''')
  parser.add_argument('filename',help='The executable file to rewrite.')
  parser.add_argument('--arch',default='arm',help='The architecture of the binary.  Default is \'ARM\'.')
  args = parser.parse_args()
  rewriter = Rewriter()
  rewriter.rewrite(args.filename,args.arch)

