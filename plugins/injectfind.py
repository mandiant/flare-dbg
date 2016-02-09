########################################################################
# Copyright 2016 FireEye
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
#
# The injectfind plugin attempts to find injected code.
# The plugin searches all memory regions and looks at the memory permissions
# and the memory type. If the memory type is private and the protection is
# executable, the plugin will print a disassembly listing and a hexdump of
# the first several bytes of the beginning of the memory region. If the
# memory region is mostly NULL bytes and more than a single page (0x1000 bytes),
# the plugin will display the beginning of the second page.
#
# usage: !py injectfind
#
# Example output:
# 0:018> .load pykd
# 0:018> !py injectfind
# ----------------------------------------------------------------
# Path: C:\WINDOWS\Explorer.EXE Pid: 632 Region: 0x1700000 - 0x1716fff Length: 0x17000
# Hex dump:
# 01700000  30 ae 80 7c 00 00 00 00-29 52 81 7c 00 00 00 00  0..|....)R.|....
# 01700010  49 73 57 6f 77 36 34 50-72 6f 63 65 73 73 00 cd  IsWow64Process..
# 01700020  e4 80 7c 00 00 00 00 47-65 74 4d 6f 64 75 6c 65  ..|....GetModule
# 01700030  48 61 6e 64 6c 65 57 00-31 b7 80 7c 00 00 00 00  HandleW.1..|....
# 01700040  47 65 74 4d 6f 64 75 6c-65 48 61 6e 64 6c 65 41  GetModuleHandleA
# 01700050  00 7b 1d 80 7c 00 00 00-00 4c 6f 61 64 4c 69 62  .{..|....LoadLib
# 01700060  72 61 72 79 41 00 c7 06-81 7c 00 00 00 00 43 72  raryA....|....Cr
# 01700070  65 61 74 65 54 68 72 65-61 64 00 0f 29 83 7c 00  eateThread..).|.
#
# Disassembly:
# 01700000 30ae807c0000    xor     byte ptr [esi+7C80h],ch
# 01700006 0000            add     byte ptr [eax],al
# 01700008 295281          sub     dword ptr [edx-7Fh],edx
# 0170000b 7c00            jl      0170000d
# 0170000d 0000            add     byte ptr [eax],al
# 0170000f 004973          add     byte ptr [ecx+73h],cl
# 01700012 57              push    edi
# 01700013 6f              outs    dx,dword ptr [esi]
#
# ----------------------------------------------------------------
# Path: C:\WINDOWS\Explorer.EXE Pid: 632 Region: 0x1cd0000 - 0x1cd0fff Length: 0x1000
# Hex dump:
# 01cd0000  b8 30 00 00 00 e9 3b d1-c3 7a 00 00 00 00 00 00  .0....;..z......
# 01cd0010  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
# 01cd0020  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
# 01cd0030  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
# 01cd0040  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
# 01cd0050  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
# 01cd0060  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
# 01cd0070  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
#
# Disassembly:
# 01cd0000 b830000000      mov     eax,30h
# 01cd0005 e93bd1c37a      jmp     ntdll!NtCreateProcessEx+0x5 (7c90d145)
# 01cd000a 0000            add     byte ptr [eax],al
# 01cd000c 0000            add     byte ptr [eax],al
# 01cd000e 0000            add     byte ptr [eax],al
# 01cd0010 0000            add     byte ptr [eax],al
# 01cd0012 0000            add     byte ptr [eax],al
# 01cd0014 0000            add     byte ptr [eax],al
#

import pykd
from flaredbg import flaredbg, utils


def main():
    """
    injectfind searches process memory for potentially injected code
    """

    process = flaredbg.get_process_obj()
    found = False

    for mbi in process.get_memory_map():
        if mbi.is_executable() and mbi.is_private():
            base_addr = mbi.BaseAddress
            size = mbi.RegionSize
                
            print '-' * 0x40
            print "Path: %s Pid: %s Region: 0x%x - 0x%x Length: 0x%x" % (process.get_image_name(), process.get_pid(), base_addr, (base_addr+size-1), size)
            
            db_res = pykd.dbgCommand('db %x' % base_addr)
            dis_res = pykd.dbgCommand('u %x' % base_addr)
            mem_bytes = process.read(base_addr, size)
            
            # Check for stripped header
            if mem_bytes[:0x1000].count('\0') > 0xfe0:
                if size > 0x2000 and mem_bytes[0x1000:0x2000].count('\0') < 0x200:
                    print "  !!! Possible stripped PE header at 0x%x\n  Showing address: 0x%x\n" % (base_addr, base_addr+0x1000)
                    db_res = pykd.dbgCommand('db %x' % (base_addr+0x1000))
                    dis_res = pykd.dbgCommand('u %x' % (base_addr+0x1000))

            # Check for legit PE
            elif utils.is_legit_pe(mem_bytes[:0x1000]):
                print "  Found legit PE at 0x%x\n" % (base_addr)
                dis_res = None

            if db_res:
                print "Hex dump:"
                print db_res
            if dis_res:
                print "Disassembly:"
                print dis_res
            print

            found = True

    if not found:
        print "Nothing found!"
                
if __name__ == '__main__':
    main()
