########################################################################
# Copyright 2015 FireEye
#
# FireEye licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
########################################################################

import PE
import envi
import flaredbg

"""
  IDA script generation functions
"""


def escape(s):
    """
    Escape single quotes/backslashes/new lines.

    Parameters:
      s : string to escape

    Returns: escapted string
    """
    if s is None:
        s = ''
    s = str(s)
    s = str(repr(s))
    s = str(s.replace('\\', '\\\\'))
    return s


def generate_ida_patch(byte_diff):
    """
    Generate idapython script to patch in byte changes.

    Parameters:
      byte_diff : dictionary of virtual addresses and hex strings of bytes to replace, created from the bgUtils.compare_memory() function

    Returns: IDA Python script to patch bytes
    """
    ida_patch_str = 'import idc\n\n'
    ida_patch_str += 'def patch_hex_str(ea, hex_str):\n'
    ida_patch_str += '    for i, b in enumerate(hex_str.decode("hex")):\n'
    ida_patch_str += '        idc.PatchByte(ea+i, ord(b))\n\n'

    for va, bytes in sorted(byte_diff.iteritems()):
        byte_str = ''.join([c for c in bytes])
        ida_patch_str += 'patch_hex_str(0x%x, "%s")\n' % (va, byte_str.encode('hex'))

    return str(ida_patch_str)


def generate_ida_comments(cmt_list, rpt=False):
    """
    Generate idapython script to make comments, optionally repeatable.

    Parameters:
      cmt_list : list that contains virtual addresses and comment strings

    Returns: IDA Python script to make comments
    """
    ida_cmt_str = 'import idc\n\n'
    ida_cmt_str += 'def append_comment(ea, cmt):\n'
    ida_cmt_str += '    current_cmt = CommentEx(ea, %d)\n' % int(rpt)
    ida_cmt_str += '    if current_cmt:\n'
    ida_cmt_str += '        cmt = "%s\\n%s\\n" % (current_cmt, cmt)\n'
    ida_cmt_str += '    idc.%s(ea, cmt)\n\n' % (("MakeRptCmt" if rpt else "MakeComm"))

    for ea, cmt in cmt_list:
        ida_cmt_str += 'append_comment(0x%x, %s)\n' % (ea, str(escape(cmt)))
        ida_cmt_str += 'print hex(0x%x), %s\n' % (ea, str(escape(cmt)))

    return str(ida_cmt_str)


def generate_ida_names(name_list):
    """
    Generate idapython script to make names.

    Parameters:
      name_list : list that contains virutal addresses and names

    Returns: IDA Python script to make names
    """
    ida_name_str = 'import idc\n\n'
    ida_name_str += 'def make_name(ea, name):\n'
    ida_name_str += '    ret = name\n'
    ida_name_str += '    if not MakeNameEx(ea, name, idc.SN_PUBLIC|SN_NOWARN):\n'
    ida_name_str += '        for i in range(0x100):\n'
    ida_name_str += '            non_collide_name = "%s_%d" % (name, i)\n'
    ida_name_str += '            if MakeNameEx(ea, non_collide_name, idc.SN_PUBLIC|SN_NOWARN):\n'
    ida_name_str += '                ret = non_collide_name\n'
    ida_name_str += '                break\n'
    ida_name_str += '    return ret\n\n'

    for ea, name in name_list:
        ida_name_str += 'make_name(0x%x, %s)\n' % (ea, str(escape(name)))
        ida_name_str += 'print hex(0x%x), %s\n' % (ea, str(escape(name)))

    return str(ida_name_str)


"""
  PE functions
"""


def is_legit_pe(bytes):
    """
    Load the memory region into a vivisect memory object and try loading the memory region as a PE "from memory".
    If it succeeds and contains valid sections, it's considered a valid PE.

    Parameters:
      bytes : byte string to test

    Returns: bool - True if legit pe, False if not
    """
    try:
        new_pe = PE.peFromBytes(bytes)

        # ImageBase will not be zero and will be page aligned
        if new_pe.IMAGE_NT_HEADERS.OptionalHeader.ImageBase == 0 or new_pe.IMAGE_NT_HEADERS.OptionalHeader.ImageBase & 0xfff != 0:
            return False

        if new_pe.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint > len(bytes):
            return False

        if new_pe.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders < 0x80:
            return False

        if new_pe.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders > len(bytes):
            return False

        # Section check
        # Start at 0x80, never seen a PE that has a VirtualAddress for the
        # first section below 0x80, usually > 0x400
        prva = 0x80
        for sect in new_pe.getSections():
            if prva > sect.VirtualAddress:
                return False
            elif sect.VirtualAddress & 0xff != 0:
                return False
            prva = sect.VirtualAddress

        # Assuming that more than 20 sections in a PE is likely bogus
        if 0 >= new_pe.IMAGE_NT_HEADERS.FileHeader.NumberOfSections > 20:
            return False

            # Could do more checks, but leaving at these, hopefully it'll be enough to rule
            # out garbage, but still catch missing MZ or DOS text stubs

    except:
        return False

    return True


def get_pe_obj(va):
    """
    Gets a vivisect PE object from a virtual address.

    Parameters:
      va : virtual address

    Returns: vivisect PE object
    """
    pu = flaredbg.ProcessUtils()
    va = pu.get_allocation_base(va)
    pbytes = pu.get_process_region_bytes(va)
    memobj = envi.memory.MemoryObject()
    memobj.addMemoryMap(va, envi.memory.MM_RWX, "", pbytes)
    pe = PE.peFromMemoryObject(memobj, va)

    return pe
