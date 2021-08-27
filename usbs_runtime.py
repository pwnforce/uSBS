from usbs_assembler import _asm

class USBSRuntime(object):
  def __init__(self,context):
    self.context = context

  def get_lookup_code(self,base,mapping_off):
	lookup = '''
    lookup:
  	push {r1}
	push {r2}  
  	mov r1,r0
	ldr r0, =%s
	ldr r2, =%s
  	sub r1, r2
	add r1, r1
	add r1, r1
	add r1, r0
	ldr r2, =%s
	add r1, r2
  	ldr r1, [r1]
  	add r0,r1
	pop {r2}  
  	pop {r1}
  	bx  lr
    '''
	return _asm( lookup%(self.context.newbase,base,mapping_off), self.context.newbase )