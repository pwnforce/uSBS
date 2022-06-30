import struct
from usbs_disassembler import USBSDisassembler
from capstone.arm import (
    ARM_CC_EQ,
    ARM_CC_NE,
    ARM_CC_HS,
    ARM_CC_LO,
    ARM_CC_MI,
    ARM_CC_PL,
    ARM_CC_VS,
    ARM_CC_VC,
    ARM_CC_HI,
    ARM_CC_LS,
    ARM_CC_GE,
    ARM_CC_LT,
    ARM_CC_GT,
    ARM_CC_LE,
    ARM_CC_AL,
    ARM_INS_EOR,
    ARM_INS_ADD,
    ARM_INS_ORR,
    ARM_INS_AND,
    ARM_INS_MOV,
    ARM_INS_CMP,
    ARM_INS_SUB,
    ARM_INS_LDR,
    ARM_INS_B,
    ARM_INS_BLX,
    ARM_INS_BL,
    ARM_INS_BX,
    ARM_REG_LR,
    ARM_OP_REG,
    ARM_REG_PC,
    ARM_INS_POP,
    ARM_OP_MEM,
    ARM_OP_IMM,
)
import logging

log = logging.getLogger(__name__)


class USBSMapper:
    def __init__(self, arch, bytes, base, entry, context):
        self.disassembler = USBSDisassembler(arch, context)
        self.bytes = bytes
        self.base = base
        self.entry = entry
        self.context = context
        if arch == "arm":
            from usbs_translator import USBSTranslator
            from usbs_runtime import USBSRuntime

            self.translator = USBSTranslator(
                context.before_push,
                context.before_push_it,
                context.before_str,
                context.before_strd,
                context.before_ret,
                context.before_ret_bxlr,
                context.before_malloc,
                self.context,
            )
            self.runtime = USBSRuntime(self.context)
            global assembler
            import usbs_assembler as assembler
        else:
            raise NotImplementedError("Architecture %s is not supported" % arch)

    def gen_mapping(self):
        log.debug("Generating mapping...")
        mapping = {}
        currmap = {}
        last = None
        for ins in self.disassembler.disasm(self.bytes, self.base):
            if isinstance(ins, list):
                # if (len(ins)==3):
                # print "TBBaddress: %s"%hex(ins[0])
                # print "TBBvalue: %s"% ins[1]
                # print "Maddress: %s"%hex(ins[0])
                # print "Mvalue: %s"% ins[1]
                currmap[ins[0]] = len(ins[1])
                continue
            # log.debug("Processing address %s"%hex(ins.address))

            if ins is not None:
                if (
                    ins.address in self.context.get_tbb_table_breakpoints_addresses()
                ):  # This is for patching TBB offset tables
                    newins = self.translator.translate_tbb_offsets(ins, mapping)
                    log.debug(
                        "Patching TBB offset table at 0x%x with new bytes %s"
                        % (ins.address, str(newins))
                    )
                elif (
                    ins.address in self.context.get_tbh_table_breakpoints_addresses()
                ):  # This is for patching TBH offset tables
                    newins = self.translator.translate_tbh_offsets(ins, mapping)
                    log.debug(
                        "Patching TBH offset table at 0x%x with new bytes %s"
                        % (ins.address, str(newins))
                    )
                else:
                    newins = self.translator.translate_one(ins, None)
                if newins is not None:
                    currmap[ins.address] = len(newins)
                    # log.debug('Translated instruction at 0x%x: len = %d, bytes: %s'%(ins.address,len(newins), str(ins.bytes)))
                else:
                    currmap[ins.address] = len(ins.bytes)
                    # log.debug('NOT Translated instruction at 0x%x: len = %d, bytes: %s'%(ins.address,len(ins.bytes), str(ins.bytes)))
        self.context.lookup_function_offset = 0
        lookup_size = len(self.runtime.get_lookup_code(self.base, 0x8F))
        offset = lookup_size

        for k in sorted(currmap.keys()):
            size = currmap[k]
            mapping[k] = offset
            offset += size
        self.context.mapping_offset = len(self.bytes) + self.base
        mapping[
            self.context.lookup_function_offset
        ] = self.context.lookup_function_offset
        mapping[len(self.bytes) + self.base] = offset
        log.debug("final offset for mapping is: 0x%x" % offset)
        # print (self.context.not_trans) # [hex(x) for x in self.context.not_trans]
        return mapping

    def gen_newcode(self, mapping):
        log.debug("Generating new code...")
        newbytes = ""
        bytemap = {}
        last = None
        currentaddr = 0x00000000
        for ins in self.disassembler.disasm(self.bytes, self.base):
            if isinstance(ins, list):
                # print "Maddress: %s"%hex(ins[0])
                # print "Mvalue: %s"% str(ins[1])
                bytemap[ins[0]] = str(ins[1])
                continue
            if ins is not None:
                # if ins.address == 0x080920b6: # TODO: remove me, only for debg
                #   print ('AAAAAAAAAAAAAAAAAAAAAAA found it')
                if (
                    ins.address in self.context.get_tbb_table_breakpoints_addresses()
                ):  # This is for patching TBB offset tables
                    newins = self.translator.translate_tbb_offsets(ins, mapping, True)
                    bytemap[ins.address] = newins
                    # log.debug('Patching TBB offset table at 0x%x with new bytes %s'%(ins.address, str(newins)))
                elif (
                    ins.address in self.context.get_tbh_table_breakpoints_addresses()
                ):  # This is for patching TBH offset tables
                    newins = self.translator.translate_tbh_offsets(ins, mapping, True)
                    bytemap[ins.address] = newins
                    # log.debug('Patching TBH offset table at 0x%x with new bytes %s'%(ins.address, str(newins)))
                else:
                    newins = self.translator.translate_one(ins, mapping)
                    if newins is not None and ins.address not in self.context.not_trans:
                        currentaddr = ins.address + len(newins)
                        # log.debug("len(newins): %d"%len(newins))
                        bytemap[ins.address] = newins
                    else:
                        currentaddr = ins.address + len(ins.bytes)
                        # log.debug("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
                        # log.debug("len(newins): %d"%len(ins.bytes))
                        bytemap[ins.address] = str(ins.bytes)
            # log.debug(hex(ins.address))
            # if hex(ins.address) == '0x80001c2':
            #   exit(0)
        newbytes += self.runtime.get_lookup_code(
            self.base, mapping[self.context.mapping_offset]
        )
        for k in sorted(bytemap.keys()):
            newbytes += bytemap[k]
        log.debug("mapping is being placed at offset: 0x%x" % len(newbytes))
        log.debug("newbyte length:%x" % len(newbytes))
        newbytes += self.write_mapping(mapping, self.base, len(self.bytes))
        return newbytes

    def write_mapping(self, mapping, base, size):
        bytes = b""
        for addr in range(base, base + size):
            if addr in mapping:
                if addr < 10:
                    log.debug("offset for 0x%x: 0x%x" % (addr, mapping[addr]))
                bytes += struct.pack("<I", mapping[addr])
            else:
                bytes += struct.pack("<I", 0xFFFFFFFF)
        log.debug("last address in mapping was 0x%x" % (base + size))
        return bytes
