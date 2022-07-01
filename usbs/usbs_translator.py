from distutils.ccompiler import new_compiler
from shutil import ExecError
from sys import dont_write_bytecode
from usbs_assembler import asm, ks_asm
import struct

# convert bytes to values
u16 = lambda x: struct.unpack("<H", x)[0]
u32 = lambda x: struct.unpack("<I", x)[0]

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
import struct
import re
from keystone import *
import binascii
import logging

log = logging.getLogger(__name__)


class USBSTranslator:
    def __init__(
        self,
        before_push,
        before_push_it,
        before_str,
        before_strd,
        before_ret,
        before_ret_bxlr,
        before_malloc,
        context,
    ):
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

    def translate_one(self, ins, mapping):
        # log.debug("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))s

        # if len(self.it_mask) > 0:
        #  print "It Mask:%s"%self.it_mask
        #  if self.it_mask[0] == 't':
        #    it_insert = self.it_bytes[self.it_cond]
        #  if self.it_mask[0] == 'e':
        #    it_insert = self.it_bytes[self.opposite[self.it_cond]]
        #  self.it_mask = self.it_mask[1:]

        transplantable = self._is_transplantable(ins)

        pattern = "^(b|bl|blx|bx)"
        pattern += "(|eq|ne|gt|lt|ge|le|cs|hs|cc|lo|mi|pl|al|nv|vs|vc|hi|ls)"
        pattern += "(|.w)$"
        match = re.search(pattern, ins.mnemonic)

        if match:
            newins = self._translate_uncond(ins, mapping)
            newins = self._prepend_pop_register(ins, newins)
            self._process_tbb_block_case(ins, newins, mapping)
            self._process_tbh_block_case(ins, newins, mapping)
            return newins

        elif ins.mnemonic.startswith("it"):
            # there is sth wrong with handling that in toggle app at
            # address 8000c3e (ittt ne) in HAL_RCC_ClockConfig function.
            return self._translate_it(ins)

        elif "ldr" in ins.mnemonic:
            # log.debug("LDR FOUND")
            newins = self._translate_ldr(ins, mapping)
            # log.debug('newins length after translation: %s'%len(newins))
            newins = self._prepend_pop_register(ins, newins)
            # log.debug('newins length after pop register: %s'%len(newins))
            self._process_tbb_block_case(ins, newins, mapping)
            self._process_tbh_block_case(ins, newins, mapping)
            return newins

        elif ins.mnemonic in ["cbz", "cbnz"]:
            newins = self._translate_cbz(ins, mapping)
            newins = self._prepend_pop_register(ins, newins)
            self._process_tbb_block_case(ins, newins, mapping)
            self._process_tbh_block_case(ins, newins, mapping)
            return newins

        # elif ins.mnemonic.startswith('push'):
        #  # for ASAN mode uncomment this and next lines
        #  # (for asan we should uncomment push, pop, str,
        #  # and bxlr in func translate_uncond)
        #  return self.translate_push(ins,mapping)
        # elif ins.mnemonic.startswith('pop'):
        #  # for ASAN mode uncomment this and next lines
        #  return self.translate_pop(ins,mapping)
        # elif ins.mnemonic.startswith('str'):
        #  # for ASAN mode uncomment this and next lines
        #  return self.translate_str(ins,mapping)

        elif ins.mnemonic.startswith("tbb"):
            # you should manually adjust the tbb by yourself with the tbb tool.
            log.debug("Found tbb instruction at 0x%x" % ins.address)
            if self.context.enable_TBB_instrumentation:
                return self._translate_tbb(ins, mapping)

        elif ins.mnemonic.startswith("tbh"):
            # you should manually adjust the tbh by yourself with the tbh tool.
            log.debug("Found tbh instruction at 0x%x" % ins.address)
            if self.context.enable_TBH_instrumentation:
                return self._translate_tbh(ins, mapping)

        elif ins.mnemonic.startswith("cmp"):
            # log.debug('Found cmp instruction at 0x%x'%ins.address)
            self._push_cmp_block(ins, mapping)
            self._dont_instrument_it_blocks()
            # TODO: enable the following lines for tbb and tbh offset
            # increase support

            # newins = self.prepend_pop_register(ins, ins.bytes)
            # self.process_tbb_block_case(ins, newins, mapping)
            # self.process_tbh_block_case(ins, newins, mapping)
            # return newins
            return None

        # elif ins.address == 0x8000f9e: #temporaryyyyy
        #  inserted= None #temporaryyyyy
        # code= b'' #temporaryyyyy
        # inserted =  self.before_malloc(ins)
        #             + "\x41\x41\x41\x41\x5d\xf8\xa0\x3c" #temporaryyyyy
        # return inserted + str(ins.bytes) #temporaryyyyy

        else:
            # Any other instruction
            if len(self.it_mask) > 0:
                # this is for dont instrumenting in IT block
                self.it_mask = self.it_mask[1:]
            newins = self._prepend_pop_register(ins, ins.bytes)
            self._process_tbb_block_case(ins, newins, mapping)
            self._process_tbh_block_case(ins, newins, mapping)
            # if(ins.address not in not_insert):
            #  inserted = self.before_inst_callback(ins)
            # if inserted is not None:
            #  return inserted + str(ins.bytes)
            return newins  # No translation needs to be done

    def translate_tbb_offsets(self, ins, mapping, force_generate=False):
        log.debug(
            "TBB: Hit a TBB breakpoint at %s. Bytes interpreted as a %s instruction"
            % (hex(ins.address), ins.mnemonic)
        )
        # log.debug("ins length: %s"%len(ins.bytes))
        if force_generate is False and (
            mapping is None or ins.address not in mapping
        ):
            newins = ins.bytes * 2
            # log.debug("length after doubleing the size: %s"%len(newins))
            return newins
        else:
            # * Return the correct and padded offsets
            newins = b""
            block_found = False
            for tbb_block in self.context.tbb_blocks:
                if ins.address >= tbb_block[
                    "offset_table_addr"
                ] and ins.address < (
                    tbb_block["offset_table_addr"] + tbb_block["table_length"]
                ):
                    # log.debug("TBB: Found a case entry in table @ 0x%x"%ins.address)
                    block_found = True
                    offsets = tbb_block["table_offsets"][
                        ins.address
                        - tbb_block["offset_table_addr"] : ins.address
                        - tbb_block["offset_table_addr"]
                        + len(ins.bytes)
                    ]
                    for i in range(len(offsets)):
                        addition = tbb_block["table_offset_additions"][
                            i + ins.address - tbb_block["offset_table_addr"]
                        ]
                        newins += struct.pack("<H", offsets[i] + addition)

            if not block_found:
                log.debug("TBB: ERROR: table @%s not found" % hex(ins.address))

            # for b in ins.bytes:
            #   newins = b + b'\x00'
            # log.debug("newins after patch: %s len:%d"%(newins, len(newins)))
            return newins

        # if True: # Disable prepend pop, only for debugging
        #   return newins
        if newins is None:
            return None
        # if mapping is not None and ins.address in mapping:
        for tbh_block in self.context.tbh_blocks:
            for case_address in tbh_block["cases_addresses"]:
                if hex(ins.address) == hex(case_address):
                    log.debug(
                        "TBH: Found a block address @ %s to prepend pop"
                        % hex(ins.address)
                    )
                    newins = (
                        asm(
                            "pop {%s}" % (tbh_block["table_address_register"]),
                            self.context.newbase,
                        )
                        + newins
                    )  # ! I probably should do this in the translator right when I process the instruction because I need to update the offsets also for the pop which is something I do there #_asm('pop %s'%tbh_block['table_address_register'], self.context.newbase)
                    return newins
        return newins
        # else:
        #   return newins

    def translate_tbh_offsets(self, ins, mapping, force_generate=False):
        log.debug(
            "TBH: Hit a TBH breakpoint at %s. Bytes interpreted as a %s instruction of length %d"
            % (hex(ins.address), ins.mnemonic, len(ins.bytes))
        )
        # log.debug("ins length: %s"%len(ins.bytes))
        if force_generate is False and (
            mapping is None or ins.address not in mapping
        ):
            newins = ins.bytes * 2  # 2 bytes offsets now become 4 bytes
            log.debug("length after doubleing the size: %s" % len(newins))
            return newins
        else:
            # * Return the correct and padded addresses
            newins = b""
            block_found = False
            for tbh_block in self.context.tbh_blocks:
                if ins.address >= tbh_block[
                    "offset_table_addr"
                ] and ins.address < (
                    tbh_block["offset_table_addr"]
                    + tbh_block["table_length"] * 2
                ):
                    log.debug(
                        "TBH: Found a case entry in table @ 0x%x" % ins.address
                    )
                    block_found = True
                    slice_lower_idx = (
                        ins.address - tbh_block["offset_table_addr"]
                    ) / 2  # Take the offsets from the current address (myself), / 2 bc 2 bytes per entry
                    slice_higher_idx = (
                        ins.address - tbh_block["offset_table_addr"]
                    ) / 2 + len(
                        ins.bytes
                    ) / 2  # Till the end, / 2 bc 2 bytes per entry
                    offsets = tbh_block["table_offsets"][
                        slice_lower_idx:slice_higher_idx
                    ]
                    for i in range(len(offsets)):
                        # TODO: For those having a 0 offset, pick the value from the next one != 0
                        addition = tbh_block["table_offset_additions"]
                        log.debug(
                            'New address for entry @ %s (newbase + mapping[tbh_block["offset_table_addr"]] + 2 * (offsets[i] + addition)): %s + %s + 2 * (%d + %d) = %s'
                            % (
                                hex(ins.address),
                                hex(self.context.newbase),
                                hex(mapping[tbh_block["offset_table_addr"]]),
                                offsets[i],
                                addition,
                                hex(
                                    self.context.newbase
                                    + mapping[tbh_block["offset_table_addr"]]
                                    + 2 * (offsets[i] + addition)
                                ),
                            )
                        )
                        newins += struct.pack(
                            "<I",
                            self.context.newbase
                            + mapping[tbh_block["offset_table_addr"]]
                            + 2 * (offsets[i] + addition),
                        )  # I may need to add a +4 according to other code using newbase + mapping

            if not block_found:
                log.debug("TBH: ERROR: table @%s not found" % hex(ins.address))

            # for b in ins.bytes:
            #   newins = b + b'\x00'
            log.debug("newins after patch: %s len:%d" % (newins, len(newins)))
            return newins

    def _is_transplantable(self, ins):
        """Return `True` if Cortex-M Thumb-2 instruction `ins` can be executed
        as a Cortex-A aarch32 Thumb-2 instruction adhering to the
        same semantics.
        Insn encodings taken from `http://class.ece.iastate.edu/cpre288/
        resources/docs/Thumb-2SupplementReferenceManual.pdf`
        """

        transplantable = False
        if len(ins.bytes) == 2:
            # 2-byte insns
            transplantable = self._is_transplantable16(ins)
        elif len(ins.bytes) == 4:
            # 4-byte insns
            transplantable = self._is_transplantable32(ins)
        else:
            log.error("Unexpected insn of length {}".format(len(ins.bytes)))
            import ipdb

            ipdb.set_trace()

        return transplantable

    def _is_transplantable16(self, ins):

        assert len(ins.bytes) == 2, "expecting 2 bytes instead of {}".format(
            len(ins.bytes)
        )

        transplantable = False
        ienc = u16(ins.bytes)
        if ienc >> 13 == 0 and ienc >> 11 != 0b11:
            # Shift by immediate, move register
            log.debug(
                "sh imm or mov reg: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> 10 == 0b000110:
            # Add / subtract register
            log.debug("add/sub reg: {} {}".format(ins.mnemonic, ins.op_str))
        elif ienc >> 10 == 0b000111:
            # Add / subtract immediate
            log.debug(
                "add/sub immediate: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> 13 == 0b001:
            # Add / subtract / compare / move immediate
            log.debug(
                "add/sub/cmp/mv immediate: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif ienc >> 10 == 0b010000:
            # Data-processing register
            log.debug(
                "data-processing reg: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> 10 == 0b010001 and (ienc >> 8) & 0b11 != 0b11:
            # Special data processing
            log.debug(
                "special data processing: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif ienc >> 8 == 0b01000111:
            # Branch/exchange instruction set
            log.debug(
                "branch/exchange insn set: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif ienc >> 11 == 0b01001:
            # Load from literal pool
            log.debug(
                "load from literal pool: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> 12 == 0b0101:
            # Load/store register offset
            log.debug(
                "load/store register offset: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif ienc >> 13 == 0b011:
            # Load/store word/byte immediate offset
            log.debug(
                "load/store word/byte immediate offset: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif ienc >> 12 == 0b1000:
            # Load/store halfword immediate offset
            log.debug(
                "load/store halfword immediate offset: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif ienc >> 12 == 0b1001:
            # load/store stack
            log.debug(
                "load/store stack: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> 12 == 0b1010:
            # add to sp or pc
            log.debug("add to sp or pc: {} {}".format(ins.mnemonic, ins.op_str))
        elif ienc >> 12 == 0b1011:
            # misc
            # TODO: need to handle misc insns
            log.debug("misc: {} {}".format(ins.mnemonic, ins.op_str))
        elif ienc >> 12 == 0b1100:
            # load/store mutliple
            log.debug(
                "load/store mutliple: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> 12 == 0b1101 and ((ienc >> 9) & 0b111) != 0b111:
            # conditional branch
            log.debug(
                "conditional branch: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> 8 == 0b11011110:
            # undefined insn
            log.debug("undefined insn: {} {}".format(ins.mnemonic, ins.op_str))
        elif ienc >> 8 == 0b11011111:
            # service system call
            log.debug(
                "service system call: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> 11 == 0b11100:
            # unconditional branch
            log.debug(
                "unconditional branch: {} {}".format(ins.mnemonic, ins.op_str)
            )
        else:
            log.debug("unknown16: {} {}".format(ins.mnemonic, ins.op_str))
            log.error("Our insn decoding is incomplete, if we end up here.")
            import ipdb
            ipdb.set_trace()

        return transplantable

    def _is_transplantable32(self, ins):

        assert len(ins.bytes) == 4, "expecting 4 bytes instead of {}".format(
            len(ins.bytes)
        )

        transplantable = False
        ienc = u16(ins.bytes[:2]) << 16 | u16(ins.bytes[2:])
        # import ipdb

        # ipdb.set_trace()
        if ienc >> (11 + 16) == 0b11110 and ((ienc >> 15) & 0b1) == 0b0:
            # Data processing: immediate, including bitfield, and saturate
            log.debug(
                "data processing imm, bitfield, saturate: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif (
            ienc >> (13 + 16) == 0b111 and ((ienc >> (9 + 16)) & 0b111) == 0b101
        ):
            # Data processing no immediate operand
            log.debug(
                "data processing no imm: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif ienc >> (9 + 16) == 0b1111100:
            # Load and store single data item
            log.debug(
                "load and store single data item: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif (
            ienc >> (9 + 16) == 0b1110100 and ((ienc >> (6 + 16)) & 0b1) == 0b1
        ):
            # Load and store, double and exclusive, and table branch
            log.debug(
                "load and store, double and exclusive, and table branch: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif (
            ienc >> (9 + 16) == 0b1110100 and ((ienc >> (6 + 16)) & 0b1) == 0b0
        ):
            # Load and store multiple, RFE and SRS
            log.debug(
                "load and store multiple, RFE and SRS: {} {}".format(
                    ins.mnemonic, ins.op_str
                )
            )
        elif ienc >> (11 + 16) == 0b11110 and ((ienc >> 15) & 0b1) == 0b1:
            # Branches, misc control
            log.debug(
                "branches, misc control: {} {}".format(ins.mnemonic, ins.op_str)
            )
        elif (
            ienc >> (13 + 16) == 0b111 and (ienc >> (8 + 16)) & 0b1111 == 0b1111
        ):
            # co-processor
            log.debug("co-processor: {} {}".format(ins.mnemonic, ins.op_str))
        else:
            log.debug("unknown32: {} {}".format(ins.mnemonic, ins.op_str))
            log.error("Our insn decoding is incomplete, if we end up here.")
            import ipdb

            ipdb.set_trace()

        return transplantable

    def _process_tbb_block_case(self, ins, newins, mapping):
        # check if address is in a tbb switch case block
        # if mapping is not None and ins.address in mapping: # ! Cannot modify the offsets if the table has already been written to the binary
        if newins is not None:
            if mapping is None or ins.address not in mapping:
                # block_found = False
                for tbb_block in self.context.tbb_blocks:
                    # log.debug("TBB: Checking if 0x%x is in a tbb block"%ins.address)

                    block_count = min(
                        len(tbb_block["cases_addresses"]),
                        len(tbb_block["cases_lengths"]),
                    )

                    for i in range(block_count):
                        base_addr, case_length = zip(
                            tbb_block["cases_addresses"],
                            tbb_block["cases_lengths"],
                        )[i]
                        # log.debug("TBB: Checking if 0x%x is in the tbb block starting @ 0x%x , %s bytes long"%(ins.address, base_addr, case_length))
                        if (
                            ins.address >= base_addr
                            and ins.address < base_addr + case_length
                        ):
                            if len(newins) != len(ins.bytes):
                                log.debug(
                                    "TBB: translated instruction is not the same size as the original instruction"
                                )

                                curr_off = tbb_block["table_offsets"][i]

                                for j in range(
                                    len(tbb_block["cases_addresses"])
                                ):  # Need to increment the offset of all the following blocks (i.e. with greater offset), not the current one
                                    if tbb_block["table_offsets"][j] > curr_off:
                                        newoffset = tbb_block["table_offsets"][
                                            j
                                        ] + ((len(newins) - len(ins.bytes)) / 2)
                                        old_offset = tbb_block[
                                            "table_offsets"
                                        ].pop(j)
                                        tbb_block["table_offsets"].insert(
                                            j, newoffset
                                        )
                                        log.debug(
                                            "TBB: old offset %s new offset: %s"
                                            % (hex(old_offset), hex(newoffset))
                                        )

                            # block_found = True
                            break
                # if block_found is False:
                #   log.debug("TBB: ERROR: instruction @ %s not found in any case block"%hex(ins.address))

    def _process_tbh_block_case(self, ins, newins, mapping):
        # check if address is in a tbh switch case block
        # if mapping is not None and ins.address in mapping: # ! Cannot modify the offsets if the table has already been written to the binary
        # if hex(ins.address) == hex(0x8001286):
        #   log.debug("TBH: FOUND: I am @ %s"%hex(ins.address))
        if newins is not None:
            if (
                mapping is None or ins.address not in mapping
            ):  # i.e. if mapping time
                # block_found = False
                for (
                    tbh_block
                ) in (
                    self.context.tbh_blocks
                ):  # for each tbh instruction in the code
                    # log.debug("TBH: Checking if 0x%x is in a tbh block"%ins.address)

                    block_count = min(
                        len(tbh_block["sorted_cases_addresses"]),
                        len(tbh_block["cases_lengths"]),
                    )  # If the instruction is in the last block is not a problem as I don't have any other offsets to increment

                    for i in range(block_count):
                        # log.debug(tbh_block['cases_addresses'])
                        # log.debug(tbh_block['cases_lengths'])
                        base_addr, case_length = zip(
                            tbh_block["sorted_cases_addresses"],
                            tbh_block["cases_lengths"],
                        )[i]
                        # log.debug("TBH: Checking if 0x%x is in the tbh block starting @ 0x%x , %s bytes long"%(ins.address, base_addr, case_length))

                        if hex(ins.address) == hex(0x8001286):
                            log.debug(
                                "TBH: translated instruction len %d is whereas original instruction len is %d @ %s <= 0x%x < %s = %s + %d"
                                % (
                                    len(newins),
                                    len(ins.bytes),
                                    hex(base_addr),
                                    ins.address,
                                    hex(base_addr + case_length),
                                    hex(base_addr),
                                    case_length,
                                )
                            )

                        # TODO: Handle cases_lengths == 0
                        # ! IDEA: Leave lengths to zero and consider the next one != 0 for doing whatever needed. When writing them down to the binary do the same.

                        if (
                            ins.address >= base_addr
                            and ins.address < base_addr + case_length
                        ):
                            # if hex(ins.address) == hex(0x8001286):
                            #   log.debug("TBH: INNNNNN translated instruction len %d is whereas original instruction len is %d @ %s <= 0x%x < %s"%(len(newins), len(ins.bytes),hex(base_addr), ins.address, hex(base_addr + case_length)))
                            if len(newins) != len(ins.bytes):
                                log.debug(
                                    "TBH: translated instruction is not the same size as the original instruction @ %s <= 0x%x < %s"
                                    % (
                                        hex(base_addr),
                                        ins.address,
                                        hex(base_addr + case_length),
                                    )
                                )

                                curr_off = sorted(tbh_block["table_offsets"])[i]
                                # log.debug("Index i is %d and curr_off is %s"%(i, hex(curr_off)))

                                for j in range(
                                    len(tbh_block["sorted_cases_addresses"])
                                ):  # Need to increment the offsets and lengths of all the following blocks (i.e. with greater offset), not the current one
                                    if tbh_block["table_offsets"][j] > curr_off:
                                        newoffset = tbh_block["table_offsets"][
                                            j
                                        ] + ((len(newins) - len(ins.bytes)) / 2)
                                        # if (newins[1] == "\xbc"): # TODO: check if this is ok. Tentative fix for offsets accounting the pop {candidate_reg} to the offset of the current block embedding the pop --> making it part of the previous block
                                        #   log.debug("TBH: Found a prepended pop instruction at %s, adjusting offset value %s by - 1*2 bytes"%(hex(ins.address), hex(newoffset)))
                                        #   newoffset = newoffset - 1 # * this may be correct but I should avoid doing it twice for blocks with 0 length
                                        old_offset = tbh_block[
                                            "table_offsets"
                                        ].pop(j)
                                        tbh_block["table_offsets"].insert(
                                            j, newoffset
                                        )
                                        log.debug(
                                            "TBH: old offset %s new offset: %s"
                                            % (hex(old_offset), hex(newoffset))
                                        )

                                # increment the current case length # TODO: if this works (seems unnecessary), do the same for the TBB case
                                # ! This is wrong bc if I increment the length of the current block, the first instruction of the next block will fall in the previous one
                                # --> I should probably do this after all the offsets have been updated
                                # new_len = case_length + (len(newins) - len(ins.bytes))
                                # tbh_block['cases_lengths'][i] = new_len
                                # log.debug("TBH: old case length %s new length: %s"%(hex(case_length), hex(new_len)))

                            # block_found = True
                            break
                # if block_found is False:
                #   log.debug("TBH: ERROR: instruction @ %s not found in any case block"%hex(ins.address))

    def _prepend_pop_register(self, ins, newins):
        # if True: # Disable prepend pop, only for debugging
        #   return newins
        if newins is None:
            return None
        # if mapping is not None and ins.address in mapping:
        for tbh_block in self.context.tbh_blocks:
            for case_address in tbh_block["cases_addresses"]:
                if hex(ins.address) == hex(case_address):
                    log.debug(
                        "TBH: Found a block address @ %s to prepend pop"
                        % hex(ins.address)
                    )
                    newins = (
                        asm(
                            "pop {%s}" % (tbh_block["table_address_register"]),
                            self.context.newbase,
                        )
                        + newins
                    )  # ! I probably should do this in the translator right when I process the instruction because I need to update the offsets also for the pop which is something I do there #_asm('pop %s'%tbh_block['table_address_register'], self.context.newbase)
                    return newins
        return newins
        # else:
        #   return newins

    def _push_cmp_block(self, ins, mapping):
        ins_addr = ins.address
        cmp_value = ins.operands[1].imm
        # log.debug("address: %s cmp_value: %d"%(hex(ins_addr),cmp_value))

        # push to a list but record only the last 5
        self.context.last_cmp_addresses.append(
            (ins_addr, cmp_value)
        )  # append the address and value of the last cmp
        if len(self.context.last_cmp_addresses) > 5:
            self.context.last_cmp_addresses = self.context.last_cmp_addresses[
                1:
            ]
        return None

    def _push_branch_block(self, ins, target, mapping):
        ins_addr = ins.address
        # log.debug("address: %s branch_value: %d"%(hex(ins_addr),cmp_value))

        # push to a list but record only the last 5
        self.context.last_branch_addresses.append(
            (ins_addr, target)
        )  # append the address and value of the last cmp
        if len(self.context.last_branch_addresses) > 5:
            self.context.last_branch_addresses = (
                self.context.last_branch_addresses[1:]
            )
        return None

    def _dont_instrument_it_blocks(self):
        if len(self.it_mask) > 0:  # this is for dont instrumenting in IT block
            self.it_mask = self.it_mask[1:]

    def _translate_it(self, ins):
        code = b""
        self.it_mask = ins.mnemonic.replace("i", "")
        self.it_cond = ins.op_str
        return None

    def _get_current_func(self, ins):
        prevfunc = None
        currfunc = None
        islast = True
        for k in sorted(self.context.flist.keys()):
            if ins.address < k - 1:
                islast = False
                currfunc = prevfunc
                break
            prevfunc = self.context.flist[k]["name"]
        if islast:
            currfunc = prevfunc
        return currfunc

    def _translate_str(self, ins, mapping):
        # print "1str"
        if len(self.it_mask) > 0:  # this is for dont instrumenting in IT block
            # print "2str"
            self.it_mask = self.it_mask[1:]
            return None
        # log.debug("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
        inserted = None
        code = b""
        operands = ins.op_str.split(", ")
        opcnt = len(operands)

        for k in range(opcnt):
            if "]" in operands[k]:
                lastoperand = k
            operands[k] = operands[k].replace("[", "")
            operands[k] = operands[k].replace("]", "")
            operands[k] = operands[k].replace("!", "")
        operands = operands[: lastoperand + 1]
        opcnt = len(operands)
        # print operands
        # print opcnt
        # if (ins.address < 0x8000b90 or ins.address > 0x8000c2c) and ins.address != 0x800a06e: #temporaryyyyy
        #  return str(ins.bytes) #temporaryyyyy

        if ins.mnemonic != "strd":
            if opcnt == 2:
                inserted = self.before_str(
                    ins,
                    operands[1],
                    None,
                    None,
                    self.context.stackaddr,
                    operands[0],
                )
                # print "inserted%s"%inserted
                return inserted + str(ins.bytes)
            elif opcnt == 3:
                inserted = self.before_str(
                    ins,
                    operands[1],
                    operands[2],
                    None,
                    self.context.stackaddr,
                    operands[0],
                )
                # print "inserted%s"%inserted
                return inserted + str(ins.bytes)
            elif opcnt == 4:
                inserted = self.before_str(
                    ins,
                    operands[1],
                    operands[2],
                    operands[3],
                    self.context.stackaddr,
                    operands[0],
                )
                # print "inserted%s"%inserted
                return inserted + str(ins.bytes)
        else:
            if opcnt == 3:
                inserted = self.before_strd(
                    ins,
                    operands[2],
                    None,
                    self.context.stackaddr,
                    operands[0],
                    operands[1],
                )
                # print "inserted%s"%inserted
                return inserted + str(ins.bytes)
            elif opcnt == 4:
                inserted = self.before_strd(
                    ins,
                    operands[2],
                    operands[3],
                    self.context.stackaddr,
                    operands[0],
                    operands[1],
                )
                # print "inserted%s"%inserted
                return inserted + str(ins.bytes)

    def _translate_pop(self, ins, mapping):
        if len(self.it_mask) > 0:  # this is for dont instrumenting in IT block
            # print "2str"
            self.it_mask = self.it_mask[1:]
            return None
        inserted = None
        code = b""
        opcnt = len(ins.operands)
        operator = ins.op_str
        # if ins.address < 0x8000b90 or ins.address > 0x8000c2c: #temporaryyyyy
        #  return str(ins.bytes) #temporaryyyyy
        if "pc" in operator:
            currfunc = self._get_current_func(ins)
            if currfunc == self.lastpoisonedfunc:
                # log.debug("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
                # print "pop %s"%opcnt
                inserted = (
                    "\x4d\xf8\x80\x2c\xef\xf3\x00\x82"
                    + self.before_ret(ins, opcnt - 1)
                    + "\x82\xf3\x00\x88\x5d\xf8\x80\x2c"
                )
                return inserted + str(ins.bytes)
        return None

    def _translate_bxlr(self, ins, mapping):
        if len(self.it_mask) > 0:  # this is for dont instrumenting in IT block
            # print "2str"
            self.it_mask = self.it_mask[1:]
            return None
        inserted = None
        code = b""
        currfunc = self._get_current_func(ins)
        # if currfunc == self.lastpoisonedfunc:
        # inserted = "\x4d\xf8\x40\x2c\xef\xf3\x00\x82" + self.before_ret(ins, -1) + "\x82\xf3\x00\x88\x5d\xf8\x40\x2c"
        #  return inserted + str(ins.bytes)
        # return str(ins.bytes) #temporaryyyyy
        if currfunc == self.lastpoisonedfunc:
            inserted = (
                "\x4d\xf8\x80\x2c\xef\xf3\x00\x82"
                + self.before_ret_bxlr(ins, -1)
                + "\x82\xf3\x00\x88\x5d\xf8\x80\x2c"
            )
            return inserted + str(ins.bytes)
        return None

    def _translate_push(self, ins, mapping):
        if len(self.it_mask) > 0:  # this is for dont instrumenting in IT block
            # print "2str"
            self.it_mask = self.it_mask[1:]
            return None

        # The following temp is an Example for stack based buffer overflow :-)
        # temp = '''
        # str r0, [sp, #-64]
        # add r0, sp, #12
        # sub r0, #8192
        # str r2, [r0]
        # ldr r0, [sp, #-64]
        # str r2, [sp, #12]
        #'''
        inserted = None
        code = b""
        operator = ins.op_str
        # if ins.address < 0x8000b90 or ins.address > 0x8000c2c: #temporaryyyyy this was for a firmware that I wanted to only sanitize one function not all instructions.
        #  return str(ins.bytes) #temporaryyyyy
        if "lr" in operator:
            currfunc = self._get_current_func(ins)
            self.lastpoisonedfunc = currfunc
            inserted = (
                "\x4d\xf8\x80\x2c\xef\xf3\x00\x82"
                + self.before_push(ins)
                + "\x82\xf3\x00\x88\x5d\xf8\x80\x2c"
            )
            # if ins.address == 0x8000e5c:     #it is just for writing on LR in function __libc_init_array in toggle app (it should be uncommented when you want to run the stack buffer overflow example which is defined in temp at the beginning of func.)
            #  return inserted + str(ins.bytes) + _asm( temp, 0x8001000 )
            return inserted + str(ins.bytes)
        return None

    def _translate_tbb(self, ins, mapping):
        # print "this is a tbb address: %s"%hex(ins.address)
        operator = ins.op_str
        log.debug("operator is %s" % operator)
        # if "[pc," in operator:
        #   tbb_addr =  ins.address + 4
        #   if mapping is not None and ins.address in mapping:
        #     tbb_addrnew = self.context.newbase + mapping[ins.address] + 4

        # print "this is a tbb pc table address: %s"% hex(tbb_addr)
        # print "this is a new tbb pc table address: %s"% hex(tbb_addrnew)
        # self.context.not_trans_tbb.append(tbb_addr)
        # self.context.not_trans_tbb.append(tbb_addr+2)

        if (
            mapping is None or ins.address not in mapping
        ):  # we're creating the mapping so need to learn the tbb structure
            log.debug("Learning TBB mapping at %s" % ins.address)

            tbb_metadata = {}
            tbb_metadata["tbb_addr"] = ins.address

            if "[pc," in operator:
                tbb_offset_table_addr = ins.address + 4
            else:
                tbb_offset_table_addr = 0xFFFFFFFF
                log.debug(
                    "ERROR: tbb offset table is somewhere else: %s" % operator
                )
                raise NotImplemented(
                    "tbb offset table is somewhere else: %s" % operator
                )
            tbb_metadata["offset_table_addr"] = tbb_offset_table_addr

            # find the last cmp operand
            assert len(self.context.last_cmp_addresses) != 0
            addr, cmp_op = self.context.last_cmp_addresses[-1]
            # log.debug("Considering last cmp at %s with value %d"%(hex(addr),int(cmp_op)))

            tbb_table_length = 1 + cmp_op

            tbb_metadata["table_length"] = tbb_table_length

            # * read the tbb_table_length offsets
            tbb_table_offsets = []
            for i in range(tbb_table_length):
                tbb_table_offsets.append(
                    self.context.read_byte(tbb_offset_table_addr + i * 1)
                )  # 1 byte offset
            tbb_metadata["table_offsets"] = tbb_table_offsets

            # * each offset needs to be increased to account for the double size of all the offsets
            table_offset_additions = []
            for _ in range(len(tbb_table_offsets)):
                new_off_addition = len(tbb_table_offsets) / 2
                table_offset_additions.append(new_off_addition)

            tbb_metadata["table_offset_additions"] = table_offset_additions

            # log.debug('Old offsets: %s'%tbb_metadata['original_table_offsets'])
            # log.debug('New offsets: %s'%tbb_metadata['table_offsets'])

            tbb_cases_code_addresses = []
            for i in range(tbb_table_length):
                tbb_cases_code_addresses.append(
                    tbb_offset_table_addr + (tbb_table_offsets[i] * 2)
                )
            tbb_metadata["cases_addresses"] = tbb_cases_code_addresses

            # * Compute case blocks lengths
            cases_code_addresses_sorted = sorted(tbb_cases_code_addresses)

            tbb_cases_lengths = []

            if (
                cases_code_addresses_sorted[0]
                != tbb_offset_table_addr + tbb_table_length
            ):  # if the first case is not adjacent to the end of the table then I assume it is a default case and I should consider it
                log.debug(
                    "WARNING: first case address is not the offset table address + table length. Assuming there's the default one there and considering it as an additional case."
                )
                # ! I'm considering the default case as an additional case but I am not incrcementing the table length / cases count
                log.debug(
                    "  First case address: %s"
                    % hex(cases_code_addresses_sorted[0])
                )
                log.debug(
                    "  Offset table address: %s + %s = %s"
                    % (
                        hex(tbb_offset_table_addr),
                        hex(tbb_table_length),
                        hex(tbb_offset_table_addr + (tbb_table_length)),
                    )
                )
                tbb_cases_lengths.append(
                    cases_code_addresses_sorted[0]
                    - (tbb_offset_table_addr + tbb_table_length)
                )

            for i in range(tbb_table_length - 1):
                tbb_cases_lengths.append(
                    cases_code_addresses_sorted[i + 1]
                    - cases_code_addresses_sorted[i]
                )

            tbb_metadata["cases_lengths"] = tbb_cases_lengths

            # * Save default case address for patching the branch (bhi) to it, if not already done somewhere else
            if (
                cases_code_addresses_sorted[0]
                != tbb_offset_table_addr + tbb_table_length
            ):  # save it if is right after the branch table
                tbb_metadata["default_case_addr"] = (
                    tbb_offset_table_addr + tbb_table_length
                )
            else:  # take the value from the branch right after the last cmp
                assert len(self.context.last_branch_addresses) != 0
                (
                    addr,
                    branch_target_address,
                ) = self.context.last_branch_addresses[-1]
                log.debug(
                    "Considering last branch at %s to target address %s"
                    % (hex(addr), hex(branch_target_address))
                )
                tbb_metadata[
                    "default_case_addr"
                ] = branch_target_address  # or addr + branch_target_offset

            assert "tbb_addr" in tbb_metadata
            assert "offset_table_addr" in tbb_metadata

            # log.debug(tbb_metadata)

            self.context.tbb_blocks.append(tbb_metadata)

            # * add breakpoints to detect when disassembling tables bytes to patch them
            for i in range(tbb_table_length):
                self.context.add_tbb_table_breakpoint(
                    tbb_offset_table_addr + 1 * i, 1
                )  # 1 byte offset for tbb instructions

            # * assemble and return the new tbh instruction
            new_operator = operator[:-1] + ", lsl #1]"
            code = asm("tbh %s" % (new_operator), self.context.newbase)
            # log.debug("New tbb->tbh code length before mapping: %d" % len(code))

            return code

        else:  # we're generating the code

            if ins.address in mapping:
                vmabase = self.context.newbase + mapping[ins.address]

                log.debug("Generating TBB->TBH code at %s" % hex(ins.address))
                new_operator = operator[:-1] + ", lsl #1]"
                code = asm("tbh %s" % (new_operator), vmabase)

                # log.debug("New tbb->tbh code length after mapping: %d" % len(code))

                return code

            else:
                log.debug(
                    "ERROR: TBB->TBH address %s is not in the mapping"
                    % hex(ins.address)
                )
                raise Exception(
                    "TBB->TBH address %s is not in the mapping"
                    % hex(ins.address)
                )

    def _translate_tbh(self, ins, mapping):
        # print "this is a tbh address: %s"%hex(ins.address)
        operator = ins.op_str
        log.debug("operator is %s" % operator)

        # if "[pc," in operator:
        #   tbh_addr =  ins.address + 4
        #   if mapping is not None and ins.address in mapping:
        #     tbh_addrnew = self.context.newbase + mapping[ins.address] + 4
        # print "this is a tbh pc table address: %s"%hex(tbh_addr)
        # print "this is a new tbh pc table address: %s"%hex(tbh_addrnew)

        if (
            mapping is None or ins.address not in mapping
        ):  # we're creating the mapping so need to learn the tbh structure
            log.debug("Learning TBH mapping at %s" % ins.address)

            tbh_metadata = {}
            tbh_metadata["tbh_addr"] = ins.address

            if "lsl #1]" not in operator:
                log.debug(
                    "ERROR: Unsupported TBH operator (only lsl #1 is supported): %s"
                    % operator
                )
                raise NotImplemented(
                    "Unsupported TBH operator (only lsl #1 is supported): %s"
                    % operator
                )

            if "[pc," in operator:
                tbh_offset_table_addr = ins.address + 4
            else:
                tbh_offset_table_addr = 0xFFFFFFFF
                log.debug(
                    "ERROR: tbh offset table is somewhere else: %s" % operator
                )
                raise NotImplemented(
                    "tbh offset table is somewhere else: %s" % operator
                )
            tbh_metadata["offset_table_addr"] = tbh_offset_table_addr

            # * find the last cmp operand to count the table length and later locate the default case
            assert len(self.context.last_cmp_addresses) != 0
            addr, cmp_op = self.context.last_cmp_addresses[-1]
            log.debug(
                "Considering last cmp at %s with value %d"
                % (hex(addr), int(cmp_op))
            )

            tbh_table_length = 1 + cmp_op  # in units, not bytes

            tbh_metadata["table_length"] = tbh_table_length

            # * read the tbh_table_length offsets
            tbh_table_offsets = []
            for i in range(tbh_table_length):
                tbh_table_offsets.append(
                    self.context.read_two_bytes(tbh_offset_table_addr + i * 2)
                )  # 2 bytes offset
            tbh_metadata["table_offsets"] = tbh_table_offsets

            # * each offset needs to be increased to account for the double size of all the offsets
            tbh_metadata["table_offset_additions"] = len(
                tbh_table_offsets
            )  # * 2

            # log.debug('Old offsets: %s'%tbh_metadata['original_table_offsets'])
            # log.debug('New offsets: %s'%tbh_metadata['table_offsets'])

            tbh_cases_code_addresses = []
            for i in range(tbh_table_length):
                tbh_cases_code_addresses.append(
                    tbh_offset_table_addr + (tbh_table_offsets[i] * 2)
                )
            tbh_metadata["cases_addresses"] = tbh_cases_code_addresses
            # log.debug([hex(a) for a in tbh_metadata['cases_addresses']])

            # * Compute case blocks lengths
            cases_code_addresses_sorted = sorted(tbh_cases_code_addresses)

            tbh_cases_lengths = []

            if cases_code_addresses_sorted[0] != tbh_offset_table_addr + (
                tbh_table_length * 2
            ):  # if the first case is not adjacent to the end of the table then I assume it is a default case and I should consider it
                log.debug(
                    "WARNING: first case address is not the offset table address + table length. Assuming there's the default one there and considering it as an additional case."
                )
                log.debug(
                    "  First case address: %s"
                    % hex(cases_code_addresses_sorted[0])
                )
                log.debug(
                    "  Offset table address: %s + (%s * 2) = %s"
                    % (
                        hex(tbh_offset_table_addr),
                        hex(tbh_table_length),
                        hex(tbh_offset_table_addr + (tbh_table_length * 2)),
                    )
                )
                # ! I'm considering the default case as an additional case but I am not incrcementing the table length / cases count
                tbh_cases_lengths.append(
                    cases_code_addresses_sorted[0]
                    - (tbh_offset_table_addr + (tbh_table_length * 2))
                )  # 2 bytes offset

            for i in range(tbh_table_length - 1):
                tbh_cases_lengths.append(
                    cases_code_addresses_sorted[i + 1]
                    - cases_code_addresses_sorted[i]
                )

            tbh_metadata["cases_lengths"] = tbh_cases_lengths
            tbh_metadata["sorted_cases_addresses"] = cases_code_addresses_sorted

            # * Save default case address for patching the branch (bhi) to it, if not already done somewhere else
            if cases_code_addresses_sorted[0] != tbh_offset_table_addr + (
                tbh_table_length * 2
            ):  # save it if is right after the branch table
                tbh_metadata["default_case_addr"] = tbh_offset_table_addr + (
                    tbh_table_length * 2
                )
            else:  # take the value from the branch right after the last cmp
                assert len(self.context.last_branch_addresses) != 0
                (
                    addr,
                    branch_target_address,
                ) = self.context.last_branch_addresses[-1]
                log.debug(
                    "Considering last branch at %s to target address %s"
                    % (hex(addr), hex(branch_target_address))
                )
                tbh_metadata[
                    "default_case_addr"
                ] = branch_target_address  # or addr + branch_target_offset

            assert "tbh_addr" in tbh_metadata
            assert "offset_table_addr" in tbh_metadata

            # * add breakpoints to detect when disassembling tables bytes to patch them
            for i in range(tbh_table_length * 2):
                self.context.add_tbh_table_breakpoint(
                    tbh_offset_table_addr + 1 * i, 1
                )  # we add also the addresses of lower bytes to detect them is the disassembler considers the higher as part of a longer instruction

            # log.debug(self.context.tbh_table_breakpoints)

            # * assemble and return the new tbh instruction
            # Here I should replace the tbh instruction with an ADR + LDR
            # new_operator = operator[:-1] + ", lsl #1]"

            arm_v7_gp_regs = [
                "r0",
                "r1",
                "r2",
                "r3",
                "r4",
                "r5",
                "r6",
                "r7",
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
            ]
            # pick a register not used as index in the table
            index_register = operator.split(", ")[1]
            # remove the_register from the list
            assert index_register in arm_v7_gp_regs
            arm_v7_gp_regs.remove(index_register)
            # register to store table address
            table_address_register = arm_v7_gp_regs[0]

            tbh_metadata["table_address_register"] = table_address_register

            log.debug(tbh_metadata)
            self.context.tbh_blocks.append(tbh_metadata)

            # backup the table address register to the stack
            # ! Later I will need to restore it in each case (including the default one)
            # TODO: For every instruction which is at the beginning of a case, I need to prepend a pop {table_address_register} instruction
            code = asm(
                "push {%s}" % (table_address_register), self.context.newbase
            )
            code += asm(
                "nop", self.context.newbase
            )  # TODO: This is for instructions alignment. Need to dinamically calculate the number of nops needed
            # TODO: MAY NEED TO FIX THE TABLE LOCATION HERE

            new_adr_operator = table_address_register + ", #8"
            log.debug("New adr operator: %s" % new_adr_operator)
            # code += _asm( 'adr %s'%(new_adr_operator),self.context.newbase)
            adr_code = asm("adr %s" % (new_adr_operator), self.context.newbase)
            adr_code = (
                adr_code[:2] + "\x04" + adr_code[3:]
            )  # replace the third byte with 0
            code += adr_code

            new_ldr_operator = (
                "pc, ["
                + table_address_register
                + ", "
                + index_register
                + ", lsl #2]"
            )  # lsl #2 for a word offset
            log.debug("New ldr operator: %s" % new_ldr_operator)
            code += asm(
                "ldr %s" % (new_ldr_operator), self.context.newbase
            )  # pc, [r3,r0,LSL#2]

            log.debug(
                "New tbh->adr|ldr code length before mapping: %d" % len(code)
            )

            return code
            # return None

            # I should replace the tbh instruction with an ADR + LDR
            # Then I need to convert the offsets in the table to absolute addresses: Before or after the offset increments? After should be ok and easier to do
            # Increment them as I would have done for offsets
            # Write them down in the new table

        else:
            if ins.address in mapping:
                vmabase = self.context.newbase + mapping[ins.address]

                arm_v7_gp_regs = [
                    "r0",
                    "r1",
                    "r2",
                    "r3",
                    "r4",
                    "r5",
                    "r6",
                    "r7",
                    "r8",
                    "r9",
                    "r10",
                    "r11",
                    "r12",
                ]
                # pick a register not used as index in the table
                index_register = operator.split(", ")[1]
                # remove the_register from the list
                assert index_register in arm_v7_gp_regs
                arm_v7_gp_regs.remove(index_register)
                # register to store table address
                table_address_register = arm_v7_gp_regs[0]

                log.debug(
                    "Generating TBH->ADR|LDR code at %s" % hex(ins.address)
                )
                code = asm(
                    "push {%s}" % (table_address_register), self.context.newbase
                )
                code += asm(
                    "nop", self.context.newbase
                )  # TODO: This is for instructions alignment. Need to dinamically calculate the number of nops needed

                new_adr_operator = table_address_register + ", #8"
                log.debug("New adr operator: %s" % new_adr_operator)
                # code += _asm( 'adr %s'%(new_adr_operator),self.context.newbase)
                adr_code = asm(
                    "adr %s" % (new_adr_operator), self.context.newbase
                )
                adr_code = (
                    adr_code[:2] + "\x04" + adr_code[3:]
                )  # replace the third byte with 0
                code += adr_code

                new_ldr_operator = (
                    "pc, ["
                    + table_address_register
                    + ", "
                    + index_register
                    + ", lsl #2]"
                )  # lsl #2 for a word offset
                log.debug("New ldr operator: %s" % new_ldr_operator)
                code += asm(
                    "ldr %s" % (new_ldr_operator), self.context.newbase
                )  # pc, [r3,r0,LSL#2]

                log.debug(
                    "New tbh->adr|ldr code length after mapping: %d" % len(code)
                )

                return code

            else:
                log.debug(
                    "ERROR: TBH->ADR|LDR address %s is not in the mapping"
                    % hex(ins.address)
                )
                raise Exception(
                    "TBH->ADR|LDR address %s is not in the mapping"
                    % hex(ins.address)
                )

    def _translate_ldr(self, ins, mapping):
        # if ins.address == 0x8000bb0: #temporaryyyyy
        #  print "we are exiting BOF!"
        #  inserted= None
        #  code= b''
        #  currfunc = self.get_current_func(ins)
        #  if currfunc == self.lastpoisonedfunc:
        #   inserted = "\x4d\xf8\x80\x2c\xef\xf3\x00\x82" + self.before_ret(ins, 0)  + "\x82\xf3\x00\x88\x5d\xf8\x80\x2c"
        #   return inserted + str(ins.bytes)
        #  return None

        it_status = False
        if len(self.it_mask) > 0:  # this is for dont instrumenting in IT block
            self.it_mask = self.it_mask[1:]
            it_status = True
        code = b""
        newtarget = self.context.newbase + 4
        newtarget_low_addr = "0x" + str(hex(newtarget))[-4:]
        newtarget_high_addr = str(hex(newtarget))[:-4]
        operator = ins.op_str
        op1 = ins.operands[0]
        reg = ins.reg_name(op1.reg)
        template = ""
        # print reg
        template = """
      movw %s, %s
      movt %s, %s
      ldr.w  %s, [%s]
      """

        if "[pc," in operator:
            match = re.search("#(0x)*([0-9a-f]+)", operator)
            if match:
                targetadd = ins.address + int(str(match.group(2)), 16) + 4
                if targetadd % 0x4 != 0:
                    targetadd -= 0x4 - targetadd % 0x4
                # print hex(targetadd)
                self.context.not_trans.append(targetadd)
                self.context.not_trans.append(targetadd + 2)
                if mapping is not None and targetadd in mapping:
                    newtarget = self.context.newbase + mapping[targetadd]
                    newtarget_low_addr = "0x" + str(hex(newtarget))[-4:]
                    newtarget_high_addr = str(hex(newtarget))[:-4]
                    vmabase = (
                        self.context.newbase + mapping[ins.address] + len(code)
                    )

                    off = newtarget - vmabase - 4
                    if vmabase % 0x4 != 0:
                        off += 2
                    # print "-------"
                    # print operator
                    # print hex(ins.address)
                    # print hex(targetadd)
                    # print hex(vmabase)
                    # print hex(newtarget)
                    # print hex(mapping[ins.address])
                    # print hex(off)
                    # print "-------"
                    if "0x" in operator:
                        operator = operator.replace(
                            "0x" + str(match.group(2)), hex(off)
                        )
                    if "0x" not in operator:
                        operator = operator.replace(
                            "#" + str(match.group(2)), "#" + hex(off)
                        )
                    # print "newoperatpr:%s"%(operator)
                    # if ".w" not in ins.mnemonic:
                    # print len(_asm( '%s.w %s'%(ins.mnemonic,operator),self.context.newbase))
                    #  print  '%s.w %s'%(ins.mnemonic,operator)
                    #  print len(_asm( '%s.w %s'%(ins.mnemonic,operator),vmabase  ))
                    #  print '%s.w %s'%(ins.mnemonic,operator)
                    #  code += _asm( '%s.w %s'%(ins.mnemonic,operator),vmabase  )
                    #  return code
                    if reg != "sp" and not it_status:
                        # print template%(reg,newtarget_low_addr, reg, newtarget_high_addr, reg, reg)
                        code += asm(
                            template
                            % (
                                reg,
                                newtarget_low_addr,
                                reg,
                                newtarget_high_addr,
                                reg,
                                reg,
                            ),
                            vmabase,
                        )
                        # if hex(ins.address) == '0x80001c2':
                        #   log.debug(template%(reg,newtarget_low_addr, reg, newtarget_high_addr, reg, reg))
                        return code
                    else:
                        if ".w" not in ins.mnemonic:
                            code += asm(
                                "%s.w %s" % (ins.mnemonic, operator), vmabase
                            )
                            # if hex(ins.address) == '0x80001c2':
                            # log.debug('%s.w %s'%(ins.mnemonic,operator))
                            return code
                        else:
                            code += asm(
                                "%s %s" % (ins.mnemonic, operator), vmabase
                            )
                            # if hex(ins.address) == '0x80001c2':
                            # log.debug('%s.w %s'%(ins.mnemonic,operator))
                            return code

                # if ".w" not in ins.mnemonic:
                #  code += _asm( '%s.w %s'%(ins.mnemonic,operator),self.context.newbase  )
                #  return code
                if reg != "sp" and not it_status:
                    code += asm(
                        template
                        % (
                            reg,
                            newtarget_low_addr,
                            reg,
                            newtarget_high_addr,
                            reg,
                            reg,
                        ),
                        self.context.newbase,
                    )
                    # log.debug(template%(reg,newtarget_low_addr, reg, newtarget_high_addr, reg, reg))
                    return code
                else:
                    if ".w" not in ins.mnemonic:
                        code += asm(
                            "%s.w %s" % (ins.mnemonic, operator),
                            self.context.newbase,
                        )
                        return code
                    else:
                        code += asm(
                            "%s %s" % (ins.mnemonic, operator),
                            self.context.newbase,
                        )
                        return code
        # if (len(code) > 0):
        #  code += str(ins.bytes)
        #  return code
        return None

    def _translate_cbz(self, ins, mapping):
        inserted = None
        op1 = ins.operands[0]
        reg = ins.reg_name(op1.reg)
        op2 = ins.operands[1]
        target = op2.imm
        template = ""
        # if(ins.address not in not_insert):
        #  inserted = self.before_inst_callback(ins)
        # if inserted is not None:
        # code += inserted
        if ins.mnemonic == "cbz":
            template = """
      cbnz %s, label
      b.w %s
      label:
      """
        elif ins.mnemonic == "cbnz":
            template = """
      cbz %s, label
      b.w %s
      label:
      """

        newtarget = self.context.newbase + 4
        if mapping is not None and target in mapping:
            newtarget = self.context.newbase + mapping[target]
            vmabase = self.context.newbase + mapping[ins.address]
            newtarget = hex(newtarget)
            # print "target: %s"%hex(target)
            # print "newtarget: %s"%newtarget
            # print ins.mnemonic
            # print vmabase

            encoding, count = self.ks.asm(template % (reg, newtarget), vmabase)
            for i, s in enumerate(encoding):
                encoding[i] = struct.pack("<B", s)
            code = "".join(encoding)
            # print code
            # print "coount%s"%count
            return code
        encoding, count = self.ks.asm(
            template % (reg, newtarget), self.context.newbase
        )
        for i, s in enumerate(encoding):
            encoding[i] = struct.pack("<B", s)
        code = "".join(encoding)
        # print code
        # print "coount%s"%count
        return code

    def _translate_uncond(self, ins, mapping):
        if len(self.it_mask) > 0:
            # this is for dont instrumenting in IT block
            self.it_mask = self.it_mask[1:]
            return None
        code = b""
        op = ins.operands[0]  # Get operand
        if op.type == ARM_OP_REG:
            # e.g. call eax or jmp ebx
            # return str(ins.bytes) # temporary
            target = ins.reg_name(op.reg)
            if str(target) != "lr":
                log.debug(
                    "! Found an indirected jump to %s at %s"
                    % (target, hex(ins.address))
                )

            # if (target=="lr"):   # for ASAN mode uncomment this and next lines
            #  return self.translate_bxlr(ins, mapping)

            if ins.mnemonic == "blx":
                log.debug(
                    "Instrumenting an indirected jump to %s at %s"
                    % (target, hex(ins.address))
                )
                return self._get_indirect_uncond_code(ins, mapping, target)
            if len(code) > 0:
                code += str(ins.bytes)
                return code
            return None

        if op.type == ARM_OP_IMM:  # e.g. bx 0x12345678
            target = op.imm
            # save the branch instruction for determining the default case
            # in tbb blocks
            self._push_branch_block(ins, target, mapping)

        if len(self.it_mask) > 0:
            # this is for dont instrumenting in IT block
            self.it_mask = self.it_mask[1:]

        elif op.type == ARM_OP_IMM:
            # e.g. call 0xdeadbeef or jmp 0xcafebada
            target = op.imm
            # if(ins.address not in not_insert):
            #  inserted = self.before_inst_callback(ins)
            # if inserted is not None:
            #  code += inserted

            # print hex(ins.address)

            newtarget = self.context.newbase + 4
            if mapping is not None and target in mapping:
                newtarget = self.context.newbase + mapping[target]
                vmabase = (
                    self.context.newbase + mapping[ins.address] + len(code)
                )
                newtarget = hex(newtarget)

                # print "target: %s"%hex(target)
                # print "newtarget: %s"%newtarget
                # print ins.mnemonic
                # print vmabase
                # print "%s : (%s+%s) = %s"%(hex(vmabase),hex(mapping[target]),hex(self.context.newbase),newtarget)
                # print '%s %s'%(ins.mnemonic,newtarget)
                code += asm("%s %s" % (ins.mnemonic, newtarget), vmabase)
                return code
                # print "new length: %s"%len(callback_code+patched)
            code += asm(
                "%s %s" % (ins.mnemonic, newtarget), self.context.newbase
            )
            return code

        if len(code) > 0:
            code += str(ins.bytes)
            return code
        return None

    def _get_indirect_uncond_code(self, ins, mapping, target):

        template = """
    str r0, [sp, #-64]
    mov r0, %s
    bl #%s
    str r0, [sp,#-8]
    ldr r0, [sp,#-64]
    add lr, pc, #5
    ldr pc, [sp,#-8]
    """  # we add 4 + 1 to the link register for the thumb bit
        # TODO: we should add the +1 depending if we're manipulating addresses referring to thumb or normal arm assembly. This is doable at instrumentation time.

        code = b""

        # inserted = self.before_inst_callback(ins)
        # if inserted is not None:
        #  code += inserted

        lookup_target = self.context.newbase
        if mapping is not None and ins.address in mapping:
            vmabase = self.context.newbase + mapping[ins.address] + len(code)
            log.debug("lookup_target::%s" % (hex(lookup_target)))
            code += asm(template % (target, lookup_target), vmabase)
            return code
        code += asm(template % (target, lookup_target), self.context.newbase)
        return code
