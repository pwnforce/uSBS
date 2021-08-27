
class Context(object):

  def __init__(self):
    self.oldbase = 0x0
    self.newbase = 0x09000000
    self.lookup_function_offset = 0x8f
    self.mapping_offset = 0x8f
    self.stackaddr = 0x20000000
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
