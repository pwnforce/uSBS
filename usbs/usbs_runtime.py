from usbs_assembler import asm


class USBSRuntime(object):
  def __init__(self,context):
    self.context = context

  def get_lookup_code(self,base,mapping_off):
	lookup = '''
    lookup:
  	push {r1,r2}
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
	adds r0,0x1
	pop {r1,r2}
  	bx  lr
    '''
	# TODO: we should use adds r0,0x1 depending if we're manipulating addresses referring to thumb or normal
	# arm assembly. It is safe to assume it is always thumb in arm IoT but it's a todo. Probably it could
	# not be done at instrumentation 	# time, or we should setup two routines, one for thumb destinations
	# and one not.
	return asm(lookup % (self.context.newbase, base, mapping_off-4), self.context.newbase)



	# * get_lookup_code breakdown:
	# save r1 and r2
	# put old target in r1
	# load newbase in r0
	# load old base in r2
	# r1 = r1 - r2 calculates the target offset from old base
	# r1 = 4 * r1 quaduplicates the offset
	# r1 = r1 + r0 adds the new base to the quadruplicated offset
	# loads in r2 the offset of the lookup table (= 0x1732)
	# adds the lookup table offset to r1 WHY?
	# loads the value pointed by r1 in r1
	# adds the value in r1 (probably the new offset) to r0 (the new base)
	# restores r2 and r1
