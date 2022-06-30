import lief
import binascii
from lief.ELF import Section


def rewrite(fname, nname, newcode, newbase):
    ls = lief.parse(fname)
    newbytes = []
    with open(newcode, "rb") as f:
        hexdata = binascii.hexlify(f.read())
        for i in map("".join, zip(hexdata[::2], hexdata[1::2])):
            newbytes.append(int(i, 16))
        newtext_section = Section()
        newtext_section.name = ".newtext"
        newtext_section.type = lief.ELF.SECTION_TYPES.PROGBITS
        newtext_section.content = newbytes
        newtext_section.add(lief.ELF.SECTION_FLAGS.EXECINSTR)
        newtext_section.add(lief.ELF.SECTION_FLAGS.ALLOC)
        newtext_section.virtual_address = newbase
        newtext_section = ls.add(newtext_section, loaded=True)
        ls.write(nname)
