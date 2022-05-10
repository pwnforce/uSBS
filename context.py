
import struct

class Context(object):

  def __init__(self):
    self.oldbase = 0x0
    self.newbase = 0x8091000 # exactly half of FLASH section (0x8021000 : 0x8100000) is 0x8090800, we do a bit more since we duplicate only the text section
    self.offset_to_file = 0
    self.lookup_function_offset = 0x8f
    self.mapping_offset = 0x8f
    self.stackaddr = 0x20000020
    self.new_entry_off = 0x8f
    self.before_push = (lambda x: None)
    self.before_push_it = (lambda x: None)
    self.before_str = (lambda x: None)
    self.before_strd = (lambda x: None)
    self.before_ret = (lambda x: None)
    self.before_ret_bxlr = (lambda x: None)
    self.before_malloc = (lambda x: None)
    self.flist = {}
    self.not_trans=[]
    self.not_trans_tbb=[]

    self.file = None # file object of the input binary

    # TBB metadata
    self.enable_TBB_instrumentation = True
    self.tbb_blocks = [] # tbb metadata list containing a dict for each tbb->tbh instruction
    self.last_cmp_addresses = [] # last n cmp instructions seen. Contains tuples (address, operand1)
    self.last_branch_addresses = [] # last n branches instructions seen. Contains tuples (address, branch_target)
    self.tbb_table_breakpoints = [] # list of (addresses, table size) of tbb tables that needs to be intercepted while the disassembler is running

  def compute_addr_offset(self):
    self.offset_to_file = 0x0101c0 - self.oldbase # TODO: set the 0x0101c0 automatically

  def read_memory(self, addr, length):
    old_pos = self.file.tell()
    self.file.seek(addr)
    value = self.file.read(length)
    self.file.seek(old_pos)
    return value

  def read_byte(self,address_elf):
    address = address_elf + self.offset_to_file
    print("reading value at address %s in elf %s" % (hex(address), hex(address_elf)))
    assert(address > 0)
    value = self.read_memory(address,1)
    print("read value: %s at address %s in elf %s" % (ord(str(value)), hex(address), hex(address_elf)))
    return struct.unpack('B',value)[0]

  def add_tbb_table_breakpoint(self, address, size):
    if address is not None and size is not None:
      self.tbb_table_breakpoints.append((address, size))
      return None
    else:
      raise Exception("Address (%s) or size (%s) are None" % (address, size))

  def get_tbb_table_breakpoints_addresses(self):
    return [x[0] for x in self.tbb_table_breakpoints]


