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

# Python imports
import os
import sys
import struct
import tempfile

# flaredbg imports
import utils
import disargfinder
# Debugger imports
import pykd
import winappdbg
# Vivisect imports
import PE
import envi

PYKD2 = 'pykd_0_2_x'
PYKD3 = 'pykd_0_3_x'


def get_process_obj(pid=None):
    """
    Convenience function to get a winappdbg process object from an active windbg session.

    Parameters:
      pid : (optional) process id

    Returns: winappdbg Process object
    """
    if pid is None:
        pykd_version = get_pykd_version()

        if pykd_version == PYKD3:
            pid = pykd.getProcessSystemID()
        else:
            pid = pykd.getCurrentProcessId()

    return winappdbg.Process(pid)


def get_pykd_version():
    """
    Gets the pykd version number 2 or 3.

    Returns: pykd version number
    """
    version = pykd.version
    version_number = int(version.replace(',', '.').replace(' ', '').split('.')[1])
    if version_number == 3:
        return PYKD3
    elif version_number == 2:
        return PYKD2
    return None


"""
  Debug utils class
"""


class DebugUtils():
    """
    Utility class that contains functions for:
      Vivisect workspace creation
      Disassmebly
      Memory snapshots/diffing
      Memory read/write/alloc/free
      Register manipulations
      Stack manipulation
      Debugger execution
      Breakpoints
      Calling functions with arguments
    """

    def __init__(self, pid=None, free_mem=True):
        """
        Initialize some variables for the DebugUtils class.

        Parameters:
          pid : (optional) process id
          free_mem : Can be set to False when debugging and do do not want the memory freed
        """
        self.alloc_mem_list = []
        self.process = get_process_obj(pid)
        self.pid = self.process.get_pid()
        self.arch = self.process.get_arch()
        self.pykd_version = get_pykd_version()
        self.free_mem = free_mem

        if self.arch == winappdbg.win32.ARCH_I386:
            self.pointer_size = 4
        else:
            self.pointer_size = 8

        self.stack = None
        self.stack_size = 0
        self.init_stack()

        self.vw = None

    def __del__(self):
        """
        Clean up all allocated memory.
        """
        if self.free_mem and self.process is not None:
            for alloc_mem in self.alloc_mem_list:
                self.free(alloc_mem)

    """
      Vivisect workspace functions
    """

    def get_workspace_from_file(self, fp, reanalyze=False):
        """
        For a file path return a workspace, it will create one if the extension
        is not .viv, otherwise it will load the existing one. Reanalyze will cause
        it to create and save a new one.

        Parameters:
          fp : file path 
          reanalyze : (optional) reanalyze the file, else pull from cache if exists
        """
        print " [+] Getting vivisect workspace."
        import vivisect  # expensive import, so let's on demand load it
        self.vw = vivisect.VivWorkspace()
        self.vw.config.viv.parsers.pe.nx = True
        if fp.endswith('.viv'):
            self.vw.loadWorkspace(fp)
            if reanalyze:
                self.vw.saveWorkspace()
        else:
            self.vw.loadFromFile(fp)
            self.vw.analyze()
            self.vw.saveWorkspace()

        print " [+] vivisect workspace load complete."

    def get_workspace_from_addr(self, addr, entry_point=None, use_pe_load=True, reanalyze=False):
        """
        Try to create a PE file given an address, then pass the created PE file to vivisect to create a workspace.
        
        Parameters:
          addr : any virtual address within a memory region
          entry_point : (optional) original entry point 
          use_pe_load : (optional) attempt to save the memory region bytes to disk and load as PE
          reanalyze : (optional) reanalyze the vivisect workspace, use this if the workspace has become stale
        """

        print " [+] Getting vivisect workspace."
        import vivisect  # expensive import, so let's on-demand load it
        pu = ProcessUtils()
        va = pu.get_allocation_base(addr)
        bytes = pu.get_process_region_bytes(va)

        storage_name = '%d_%x_%x' % (self.process.get_pid(), va, len(bytes))

        self.vw = vivisect.VivWorkspace()

        temp_dir = tempfile.gettempdir()
        storage_fname = '%s\\%s.viv' % (temp_dir, storage_name)

        # Don't reanalyze the workspace, try to grab a cached one even if stale
        if not reanalyze and os.path.exists(storage_fname):
            self.vw.loadWorkspace(storage_fname)
        # Reanalyze and create new workspace
        else:
            self.vw.setMeta('Architecture', self.arch)
            self.vw.setMeta('Platform', 'windows')
            self.vw.setMeta('Format', 'pe')
            self.vw.config.viv.parsers.pe.nx = True

            if utils.is_legit_pe(bytes) and use_pe_load:
                import vivisect.parsers.pe
                fname = '%s\\%s.mem' % (temp_dir, storage_name)
                open(fname, 'wb').write(bytes)
                f = file(fname, 'rb')
                peobj = PE.PE(f, inmem=True)
                peobj.filesize = len(bytes)
                vivisect.parsers.pe.loadPeIntoWorkspace(self.vw, peobj, fname)
                if entry_point:
                    self.vw.addEntryPoint(entry_point)
                self.vw._snapInAnalysisModules()
            else:
                import vivisect.parsers.pe
                import envi.memory
                import vivisect.const
                defcall = vivisect.parsers.pe.defcalls.get(self.arch)
                self.vw.setMeta("DefaultCall", defcall)
                self.vw.addMemoryMap(va, envi.memory.MM_RWX, "", bytes)
                pe = None
                if utils.is_legit_pe(bytes):
                    pe = utils.get_pe_obj(va)
                if not entry_point and pe:
                    entry_point = pe.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint + va
                if entry_point:
                    self.vw.addEntryPoint(entry_point)
                    self.vw.addExport(entry_point, vivisect.const.EXP_FUNCTION, '__entry', '')
                if pe:
                    self.vw.addVaSet("Library Loads",
                                     (("Address", vivisect.const.VASET_ADDRESS), ("Library", vivisect.const.VASET_STRING)))
                    self.vw.addVaSet('pe:ordinals',
                                     (('Address', vivisect.const.VASET_ADDRESS), ('Ordinal', vivisect.const.VASET_INTEGER)))
                    # Add exports
                    for rva, _, expname in pe.getExports():
                        self.vw.addExport(
                            va + rva, vivisect.const.EXP_UNTYPED, expname, '')
                    # Add imports
                    for rva, lname, iname in pe.getImports():
                        if self.vw.probeMemory(rva + va, 4, envi.memory.MM_READ):
                            self.vw.makeImport(rva + va, lname, iname)

                self.vw._snapInAnalysisModules()

            # save the analysis
            self.vw.setMeta("StorageModule", "vivisect.storage.basicfile")
            self.vw.setMeta("StorageName", storage_fname)

            self.vw.analyze()
            self.vw.saveWorkspace()
        print " [+] vivisect workspace load complete."

    """
      Disassmebly
    """

    def disasm(self, va):
        """
        Use vivisect disassembler to disassemble at a specific virtual address, only supporting i386/amd64

        Parameters:
          va : virtual address to disassemble

        Returns: vivisect opcode
        """
        if self.arch == winappdbg.win32.ARCH_I386:
            import envi.archs.i386
            d = envi.archs.i386.disasm.i386Disasm()
        else:
            import envi.archs.amd64
            d = envi.archs.amd64.disasm.Amd64Disasm()
        try:
            bytes = self.read_memory(va, 16)
            ret = d.disasm(bytes, 0, va)
        except AccessViolationException:
            ret = None
        return ret

    def wdbg_get_mnem(self, va):
        """
        Use windbg disassembler to disassemble at a specific address and return only the mnem. Much faster than using
        self.disasm, but only gets the mnem.

        Args:
            va: virtual address to disassemble

        Returns: text opcode

        """
        mnem = None
        d = pykd.disasm(va)
        inst = d.instruction()
        inst_elements = filter(None, inst.split(' '))
        if len(inst_elements) > 2:
            mnem = inst_elements[2]
        return mnem

    """
      Memory snapshots/diffing
    """

    def snapshot_memory(self, start_va, end_va):
        """
        Creates a memory snapshot.

        Parameters:
          start_va : starting virtual address
          end_va : ending virtual address

        Returns: dictionary containing start/end virtual address, length, and byte string
        """
        length = end_va - start_va
        snapshot = {}
        if length > 0:
            snapshot['start_va'] = start_va
            snapshot['end_va'] = end_va
            snapshot['length'] = length
            snapshot['bytes'] = ''

            try:
                mem_bytes = self.read_memory(start_va, length)
            except AccessViolationException:
                print ' [-] Error reading bytes!'
                mem_bytes = ''

            snapshot['bytes'] = mem_bytes

        return snapshot

    def compare_memory(self, orig, new):
        """
        Compare two memory snapshots, an original snapshot and a new snapshot.

        Parameters:
          orig : first snapshot
          new : second snapshot

        Returns: dictionary containing virtual addresses and modified byte string
        """
        diff = {}
        if 'bytes' in orig and 'bytes' in new and 'length' in orig:
            if orig['length'] == len(orig['bytes']) == len(new['bytes']) > 0:
                if orig['start_va']:
                    run_start = 0

                    for i in range(len(orig['bytes'])):
                        if new['bytes'][i] != orig['bytes'][i]:
                            if run_start == 0:
                                run_start = orig['start_va'] + i
                                diff[run_start] = []
                            diff[run_start].append(new['bytes'][i])
                        else:
                            run_start = 0
        return diff

    """
      Memory functions
        Read
        Write
        Allocate
        Free
    """

    def is_memory_readable(self, va, length):
        """
        Wrapper for reable memory check.

        Parameters:
          va : virtual address to check
          length : length of memory to check

        Returns: bool - True if readable, False if not
        """
        return self.process.is_buffer_readable(va, length)

    def is_memory_writeable(self, va, length):
        """
        Wrapper for writeable memory check.

        Parameters:
          va : virtual address to check
          length : length of memory to check

        Returns: bool - True if writeable, False if not
        """
        return self.process.is_buffer_writeable(va, length)

    def is_memory_executable(self, va, length):
        """
        Wrapper for executable memory check.

        Parameters:
          va : virtual address to check
          length : length of memory to check

        Returns: bool - True if executable, False if not
        """
        return self.process.is_buffer_executable(va, length)

    def read_memory(self, va, length):
        """
        Memory reader wrapper.

        Parameters:
          va : virtual address to read
          length : length to read

        Returns: read bytes
        """
        if va and self.is_memory_readable(va, length):
            bytes = self.process.read(va, length)
        else:
            raise AccessViolationException(va)
        return bytes

    def read_char(self, va):
        """
        Read single byte.

        Parameters:
          va : virtual address of char

        Returns: char as integer
        """
        return ord(self.read_memory(va, 1))

    def read_byte(self, va):
        """
        Read single byte.

        Parameters:
          va : virtual address of char

        Returns: char
        """
        return self.read_char(va)

    def read_word(self, va):
        """
        Read two byte word

        Parameters:
          va : virtual address of word

        Returns: word
        """
        word = self.read_memory(va, 2)
        return struct.unpack('<H', word)[0]

    def read_dword(self, va):
        """
        Read dword

        Parameters:
          va : virtual address of dword

        Returns: dword
        """
        dword = self.read_memory(va, 4)
        return struct.unpack('<I', dword)[0]

    def read_qword(self, va):
        """
        Read qword

        Parameters:
          va : virtual address of qword

        Returns: qword
        """
        qword = self.read_memory(va, 8)
        return struct.unpack('<Q', qword)[0]

    def read_pointer(self, va):
        """
        Read system pointer size wrapper.

        Parameters:
          va : virtual address to read

        Returns: DWORD or QWORD at a virtual address
        """
        if self.process.is_address_readable(va):
            addr = self.process.read_pointer(va)
        else:
            raise AccessViolationException(va)
        return addr

    def read_string(self, va, max_length=0x1000):
        """
        Read a string, figure out if it is a Null terminated C-style string or if it is a UTF-16 unicode string.

        Parameters:
          va : virtual address for start of string

        Returns: string
        """
        out_str = ''
        utf_16 = False
        for i in range(max_length):
            c = chr(self.read_char(va))
            if utf_16:
                c += chr(self.read_char(va + 1))
                if c[1] != '\0':
                    utf_16 = False
                    out_str = out_str[0]
                    break
                va += 1
            # Only looking for Latin languages utf-16 strings or length 2 or more
            if c is None or c == '\0' or c == '\0\0':
                if len(out_str) == 1 and chr(self.read_char(va + 1)) != '\0' and chr(self.read_char(va + 2)) == '\0':
                    utf_16 = True
                else:
                    break
            out_str += c
            va += 1
        if utf_16:
            out_str = out_str.decode('utf-16')
        return out_str

    def write_memory(self, va, bytes):
        """
        Memory writer wrapper.

        Parameters:
          va : virtual address to write
          bytes : bytes to write
        """
        if self.is_memory_writeable(va, len(bytes)):
            self.process.write(va, bytes)
        else:
            raise AccessViolationException(va)

    def write_char(self, va, char):
        """
        Write single byte.

        Parameters:
          va : virtual address to write char
          char : single byte
        """
        if type(char) in (int, long):
            char = chr(char & 0xff)
        else:
            char = char[0]
        self.write_memory(va, char)

    def write_byte(self, va, byte):
        """
        Write single byte.

        Parameters:
          va : virtual address to write byte
          byte : single byte
        """
        self.write_char(va, byte)

    def write_word(self, va, word):
        """
        Write word.

        Parameters:
          va : virtual address to write char
          word : word value as integer
        """
        word = struct.pack('<H', word)
        self.write_memory(va, word)

    def write_dword(self, va, dword):
        """
        Write word.

        Parameters:
          va : virtual address to write char
          dword : dword value as integer
        """
        dword = struct.pack('<I', dword)
        self.write_memory(va, dword)

    def write_qword(self, va, qword):
        """
        Write word.

        Parameters:
          va : virtual address to write char
          qword : qword value as integer
        """
        qword = struct.pack('<I', qword)
        self.write_memory(va, qword)

    def write_pointer(self, va, val):
        """
        Write pointer.

        Parameters:
          va : virtual address to write
          val : val to write
        """
        if self.arch == winappdbg.win32.ARCH_I386:
            fmt = '<I'
        else:
            fmt = '<Q'

        bytes = struct.pack(fmt, val)
        self.write_memory(va, bytes)

    def malloc(self, size, va=None):
        """
        malloc wrapper with memset.

        Parameters:
          size : size of memory block in bytes
          va : (optional) requested virtual address

        Returns: allocated memory virtual address
        """
        m_addr = self.process.malloc(size, va)
        self.memset(m_addr, 0, size)

        self.alloc_mem_list.append(m_addr)

        return m_addr

    def free(self, va):
        """
        free wrapper.

        Parameters:
          va : virtual address to free
        """
        self.process.free(va)
        if va in self.alloc_mem_list:
            self.alloc_mem_list.remove(va)

    def memset(self, va, value, num):
        """
        memset wrapper.

        Parameters:
          va : virtual address to memset
          value : value to fill
          num : size
        """
        new_val = '\0'
        if isinstance(value, str):
            new_val = value[0]
        elif isinstance(value, int) or isinstance(value, long):
            new_val = chr(value & 0xff)
        self.write_memory(va, new_val * num)

    """
      Register functions
    """

    def set_pc(self, va):
        """
        Set the program counter convenience function.

        Parameters:
          va : virtual address to set program counter
        """
        if self.arch == winappdbg.win32.ARCH_I386:
            pc_reg = 'eip'
        else:
            pc_reg = 'rip'

        self.set_reg(pc_reg, va)

    def get_pc(self):
        """
        Get the program counter convenience function.

        Returns: program counter virtual address
        """
        if self.arch == winappdbg.win32.ARCH_I386:
            pc_reg = 'eip'
        else:
            pc_reg = 'rip'

        return self.get_reg(pc_reg)

    def set_reg(self, reg, val):
        """
        Sets a register to a new value.

        Parameters:
          reg : name of the register to set
          val : value to set
        """
        cmd = 'r %s=%x' % (reg, val)
        pykd.dbgCommand(cmd)

    def get_reg(self, reg):
        """
        Gets a register value

        Parameters:
          reg : name of register to get

        Returns: register value
        """
        return int(pykd.reg(reg))

    """
      Stack functions
    """

    def init_stack(self, size=0x10000):
        """
        Make our own stack.

        Parameters:
          size : (optional) size of stack
        """
        if size < 0x2000:
            size = 0x2000
        self.stack = self.malloc(size)
        self.stack_size = size

    def get_sp_reg_name(self):
        """
        Helper function to get the stack register for 32/64 bit systems.

        Returns: stack pointer name - ESP or RSP
        """
        if self.arch == winappdbg.win32.ARCH_I386:
            sp = 'esp'
        else:
            sp = 'rsp'
        return sp

    def init_stack_pointer(self):
        """
        Sets the stack pointer.
        """
        sp = self.get_sp_reg_name()
        stack_pointer = self.stack + self.stack_size - 0x1000

        if self.arch == winappdbg.win32.ARCH_I386:
            bp = 'ebp'
        else:
            bp = 'rbp'

        self.set_reg(bp, stack_pointer)
        self.set_reg(sp, stack_pointer)

    def get_stack_pointer(self):
        """
        Gets the stack address at the stack pointer.

        Returns: stack pointer virtual address
        """
        sp = self.get_sp_reg_name()
        return self.get_reg(sp)

    def set_return_addr(self, va):
        """
        Writes a virtual address at the stack pointer.

        Parameters:
          va : virtual address to set as return addr
        """
        sp_addr = self.get_stack_pointer()
        self.write_pointer(sp_addr, va)

    def calc_return_addr(self, call_addr):
        """
        Gets the return address given an address with a call instruction.

        Parameters:
          call_addr = virtual address of call

        Returns: return address
        """
        ret_addr = None
        op = self.disasm(call_addr)
        if op.mnem == 'call':
            ret_addr = call_addr + op.size
        return ret_addr

    def setup_stack(self, stack_args):
        """
        Sets up the stack for a function to be called.

        Parameters:
          stack_args : list of values to set as arguments on the stack
        """
        sp = self.get_sp_reg_name()

        offset = self.pointer_size
        stack_pointer = self.get_stack_pointer()
        for arg in stack_args:
            addr = stack_pointer + offset
            self.write_pointer(addr, arg)
            offset += self.pointer_size

    """
      Debugger execution functions
    """

    def go(self):
        """
        Go wrapper.
        """
        pykd.dbgCommand('sxe -h av')
        access_violation_handler = AccessViolationExceptionHandler()
        # Go
        pykd.go()
        if access_violation_handler.except_addr:
            pykd.dbgCommand('sxe av')
            raise AccessViolationException(access_violation_handler.except_addr)
        elif access_violation_handler.second_chance:
            pykd.dbgCommand('sxe av')
            raise SecondChanceException()
        elif access_violation_handler.ctrlbr:
            pykd.dbgCommand('sxe av')
            raise ControlBreakException()

    def run(self):
        """
        Same as go().
        """
        self.go()

    def run_to_va(self, va):
        """
        Run until a specific virtual address.

        Parameters:
          va : virtual address to run until hit
        """
        while True:
            self.step()
            ea = self.get_pc()
            if va == ea:
                break

    def run_to_va_bp(self, va):
        """
        Run until a specific virtual address using breakpoints.

        Parameters:
          va : virtual address to run until hit
        """
        self.set_breakpoint([va, ])

    def run_to_mnem(self, mnem):
        """
        Wrapper for the windbg pt command to run until a return.

        Parameters:
          mnem : opcode mnemonic
        """
        while True:
            self.step()
            ea = self.get_pc()
            c_mnem = self.wdbg_get_mnem(ea)
            if c_mnem is None or c_mnem == mnem:
                break

    def run_to_return(self):
        """
        Wrapper for run_to_mnem until a ret is found.
        """
        self.run_to_mnem('ret')

    def run_to_ret(self):
        """
        Wrapper for run_to_mnem until a ret is found.
        """
        self.run_to_return()

    def step_out(self):
        """
        Run until a ret, then make the return.
        WARNING: This may not work if the function does not return!
        """
        if self.pykd_version == PYKD3:
            pykd.dbgCommand('sxe -h av')
            access_violation_handler = AccessViolationExceptionHandler()
            # Step out
            pykd.stepout()
            if access_violation_handler.except_addr:
                pykd.dbgCommand('sxe av')
                raise AccessViolationException(access_violation_handler.except_addr)
            elif access_violation_handler.second_chance:
                pykd.dbgCommand('sxe av')
                raise SecondChanceException()
            elif access_violation_handler.ctrlbr:
                pykd.dbgCommand('sxe av')
                raise ControlBreakException()
        else:
            self.run_to_return()
            self.step()

    def step(self):
        """
        Single step and step over call functions.
        """
        pykd.dbgCommand('sxe -h av')
        access_violation_handler = AccessViolationExceptionHandler()
        # Step
        pykd.step()
        if access_violation_handler.except_addr:
            pykd.dbgCommand('sxe av')
            raise AccessViolationException(access_violation_handler.except_addr)
        elif access_violation_handler.second_chance:
            pykd.dbgCommand('sxe av')
            raise SecondChanceException()
        elif access_violation_handler.ctrlbr:
            pykd.dbgCommand('sxe av')
            raise ControlBreakException()

    def step_over(self):
        """
        Single step and step over call functions.
        """
        self.step()

    def trace(self):
        """
        Single step into - follow calls.
        """
        pykd.dbgCommand('sxe -h av')
        access_violation_handler = AccessViolationExceptionHandler()
        # Trace
        pykd.trace()
        if access_violation_handler.except_addr:
            pykd.dbgCommand('sxe av')
            raise AccessViolationException(access_violation_handler.except_addr)
        elif access_violation_handler.second_chance:
            pykd.dbgCommand('sxe av')
            raise SecondChanceException()
        elif access_violation_handler.ctrlbr:
            pykd.dbgCommand('sxe av')
            raise ControlBreakException()

    def step_in(self):
        """
        Single step into - follow calls.
        """
        self.trace()

    def stepi(self):
        """
        Single step into - follow calls.
        """
        self.trace()

    def set_args(self, args):
        """
        Sets up arguments given a list of args.

        An example args parameter could be this:
            [{'ecx': 5}, {'edx': 8}, 7, 9]

            This example would set ecx to 5, edx to 8, and then push 7 and 9 onto the stack

        Parameters:
          args : list of arguments
        """
        push_args = []
        for arg in args:
            if isinstance(arg, dict):
                reg, val = arg.iteritems().next()
                self.set_reg(reg, val)
            else:
                push_args.append(arg)
        self.setup_stack(push_args)

    def call(self, fva, args, fromva=None, tova=None):
        """
        Simple call function wrapper.

        Accepts a function start va and the arguments and optionally the from virtual address to setup the return address on the stack.

        Parameters:
          fva : function virtual address
          args : list of arguments
          fromva : (optional) calling virtual address, sets the return address on the stack
          tova : (optional) overrides the run_to_return, instead run to a specific address, could be used for the last address of the function
        """
        self.set_pc(fva)
        self.init_stack_pointer()
        if fromva is not None:
            return_addr = self.calc_return_addr(fromva)
            if return_addr is not None:
                self.set_return_addr(return_addr)
        self.set_args(args)
        if tova:
            # avoid single stepping through a decoder func
            self.run_to_va_bp(tova)
        else:
            self.run_to_return()

        if self.arch == winappdbg.win32.ARCH_I386:
            ret_reg = 'eax'
        else:
            ret_reg = 'rax'

        return self.get_reg(ret_reg)

    """
      Threads
    """

    def suspend_threads(self):
        """
        Suspends all threads except the current thread.
        """
        if self.pykd_version == PYKD3:
            current_thread_id = pykd.getThreadSystemID()
        else:
            current_thread_id = pykd.getCurrentThreadId()
        for thread in self.process.iter_threads():
            if thread.is_alive() and thread.get_tid() != current_thread_id:
                thread.suspend()

    def resume_threads(self):
        """
        Resumes all threads.
        """
        for thread in self.process.iter_threads():
            if thread.is_alive():
                thread.resume()

    """
      Breakpoints
    """

    def set_breakpoint(self, addrs):
        """
        Sets regular software breakpoints and runs until one is hit.

        Parameters:
          addrs : list of virtual addresses

        Returns: virtual address of breakpoint that was hit
        """
        handler = BreakpointExceptionHandler(addrs)
        self.go()
        if handler.bp_hit_addr is None:
            if handler.ctrlbr:
                print "Ctrl+Break received, stopping script."
                raise ControlBreakException()
            if handler.av:
                raise AccessViolationException(handler.except_addr)
            # Hit a breakpoint that wasn't set by us
            print "Hit new breakpoint"
            sys.exit()
        return handler.bp_hit_addr

    def set_mem_breakpoint(self, addrs, ignore_access=True):
        """
        Sets a memory breakpoint and runs until the memory breakpoint is hit. Only breaks on code execution, not memory access! Uses guard pages.
        Does not work if the memory region's page permissions change. You need to handle this on your own.

        Parameters:
          addrs : list of virtual addresses

        Returns: virtual address of memory breakpoint that was hit
        """
        # Set the exception filter policy to handle guard page exceptions
        pykd.dbgCommand('sxe -h gp')
        handler = PageGuardExceptionHandler(self.process, addrs)

        # Run until the breakpoint has been hit
        while not handler.bp_hit and not handler.mem_access:
            pykd.go()
            # If just memory access and not execution, just step
            if ignore_access and handler.mem_access:
                pykd.step()
                handler = PageGuardExceptionHandler(self.process, addrs)

        # Restore default exception filter policy for guard page exceptions
        pykd.dbgCommand('sxe gp')

        if handler.ctrlbr:
            print "Ctrl+Break received, stopping script."
            sys.exit()
        elif handler.av:
            raise AccessViolationException(handler.except_addr)
        elif handler.second_chance:
            raise SecondChanceException()

        return handler.except_addr

    def set_access_breakpoint(self, addrs):
        """
        Sets a breakpoint on a memory region by changing the page permissions to remove the executable permission.
        Similar to the memory breakpoint, this does not work if the memory region's page permissions change. You need to handle this on your own.
        WARNING: will not work on XP if the NXCOMPAT flag is set. Some packers set this flag to avoid DEP.

        Parameters:
          addrs : list of virtual addresses

        Returns: virtual address of access violation breakpoint that was hit
        """
        # Set the exception filter policy to handle guard page exceptions
        pykd.dbgCommand('sxe -h av')
        handler = AccessViolationExceptionHandler(self.process, addrs)

        # Run until the breakpoint has been hit
        while not handler.bp_hit:
            pykd.go()
            if handler.av:
                break

        # Restore default exception filter policy for guard page exceptions
        pykd.dbgCommand('sxe av')

        if handler.ctrlbr:
            print "Ctrl+Break received, stopping script."
            sys.exit()
        elif handler.av:
            raise AccessViolationException(handler.except_addr)
        elif handler.second_chance:
            raise SecondChanceException()

        return handler.except_addr

    """
      Get function arguments using vivisect
    """

    def get_reg_arg(self, args, reg_name):
        """
        Convenience function to grab a register arg given the name.

        Parameters:
          args : list of arguments
          reg_name : register name of argument to grab.

        Returns: value of register argument
        """
        out = None
        for arg in args:
            if isinstance(arg, dict):
                reg, val = arg.iteritems().next()
                if reg == reg_name:
                    out = val
                    break
        return out

    def set_reg_arg(self, args, reg_name, value):
        """
        Convenience function to set a register arg, assuming the register name is already in the arguments list.

        Parameters:
          args : list of arguments
          reg_name : register name
          value : value to set

        Returns: modified argument list
        """
        reg_set = False
        for i, arg in enumerate(args):
            if isinstance(arg, dict):
                reg, val = arg.iteritems().next()
                if reg == reg_name:
                    arg[reg] = value
                    args[i] = arg
                    reg_set = True
                    break
        if not reg_set:
            args.append({reg_name:value})
        return args

    def clean_args(self, arg_lists):
        """
        Change the arg_list from Jay's argtracker format to the format used by this script.

        Parameters:
          arg_lists : list of argument lists

        Returns: modified argument list
        """
        args_out = []
        for arg_list in arg_lists:
            args = []
            for arg_type, arg_val in sorted(arg_list.iteritems()):
                if isinstance(arg_type, int) or isinstance(arg_type, long):
                    args.append(arg_val[1])
                else:
                    if args:
                        args.insert(0, {arg_type: arg_val[1]})
                    else:
                        args.append({arg_type: arg_val[1]})
            args_out.append(args)
        return args_out

    def get_call_list(self, fva, num_push_args, regs=[]):
        """
        Given a function virtual address, get all xrefs and use Jay's argtracker to get the arguments
        return the xrefs with args.

        Example parameters:
            get_call_list(fva, 2, ['ecx', 'edx'])

        Example return value:
            [func_xref_va, [{'reg1': arg0}, {'reg2':arg1}, arg2, arg3]]

        Parameters:
          fva : function virtual address 
          num_push_args : number of push arguments
          regs : list of register names

        Returns: list of calling virtual addresses with their associated arguemnts
        """
        call_list = []
        if self.vw is None:
            self.get_workspace_from_addr(fva)
        try:
            import vivargtracker
            tracker = vivargtracker.ArgTracker(self.vw)
        except ImportError:
            vivargtracker = False
        for fromva, tova, rtype, flags in self.vw.getXrefsTo(fva):
            if vivargtracker:
                arg_lists = tracker.getPushArgs(fromva, num_push_args, regs)
            if vivargtracker and arg_lists:  # Try arg tracker emulation
                cleaned_arg_lists = self.clean_args(arg_lists)
            else:  # If emulation fails or cannot import, default to naively looking for immediate values
                cleaned_arg_lists = disargfinder.find_args(self.vw, fromva, num_push_args, regs)
            for cleaned_arg_list in cleaned_arg_lists:
                call_list.append((fromva, cleaned_arg_list))
        return call_list

    def get_call_list_auto(self, fva):
        """
        Given a function virtual address, get the arguments, and pass them to get_call_list.

        Parameters:
          fva : function virtual address

        Returns: list of calling virtual addresses with their associated arguments
        """
        call_list = []

        if self.vw is None:
            self.get_workspace_from_addr(fva)
        f_args = self.vw.getFunctionArgs(fva)
        reg_args = []
        push_args = []
        for arg_type, arg_name in f_args:
            if arg_name.startswith('arg'):
                push_args.append(arg_name)
            else:
                reg_args.append(arg_name)

        call_list = self.get_call_list(fva, len(push_args), reg_args)
        return call_list


class ProcessUtils:
    """
    Process utility class
    """

    def __init__(self, pid=None):
        """
        Initializes the ProcessUtils class.

        Parameters:
          pid : (optional) process id
        """
        self.process = self.process = get_process_obj(pid)
        self.arch = self.process.get_arch()
        self.module_exports = None

    def find_imports(self, base_va):
        """
        Finds all DLL function pointers within a memory region.

        Parameters:
          base_va : base virtual address

        Returns: dictionary of found imports
        """
        imports = {}
        current_addr = base_va
        mem_bytes = self.get_process_region_bytes(base_va)

        module_exports = self.get_exports()

        if self.arch == winappdbg.win32.ARCH_I386:
            fmt = '<I'
            pointer_size = 4
        elif self.arch == winappdbg.win32.ARCH_AMD64:
            fmt = '<Q'
            pointer_size = 8
        else:
            return None

        export_addrs = []
        for _, exp in module_exports.iteritems():
            export_addrs += exp.keys()

        fast_search = {}
        for addr in export_addrs:
            for i in range(6):
                if i > 0:
                    if addr + i in export_addrs:
                        break
                paddr = struct.pack(fmt, addr + i)
                most_bytes = paddr[2:]
                if most_bytes in fast_search:
                    fast_search[most_bytes].append((paddr[:2], addr))
                else:
                    fast_search[most_bytes] = []
                    fast_search[most_bytes].append((paddr[:2], addr))

        for search_bytes, small_bytes_list in fast_search.iteritems():
            current_offset = 0
            found_offset = 0
            while found_offset >= 0:
                found_offset = mem_bytes[current_offset:].find(search_bytes) - 2

                if found_offset >= 0:
                    current_offset += found_offset

                    current_small_bytes = mem_bytes[current_offset:current_offset + 2]
                    exp_addr = 0
                    for small_bytes, addr in small_bytes_list:
                        if small_bytes == current_small_bytes:
                            exp_addr = addr
                            break
                    if exp_addr:
                        found_addr = base_va + current_offset

                        for dll, exp in module_exports.iteritems():
                            if exp_addr in exp:
                                func_dll = dll
                                func_name = exp[exp_addr]
                        imports[found_addr] = {}
                        import_func = {}
                        import_func["func_name"] = func_name
                        import_func["func_dll"] = func_dll

                        imports[found_addr] = import_func
                    current_offset += 3

        return imports

    def resolve_func_by_addr(self, va):
        """
        Find exported function name by address. Search 8 bytes in to the function.

        Parameters:
          va : virtual address of exported function

        Returns: function name or empty string if nothing found
        """
        exports = self.get_exports()
        func_name = ''
        for dll, exp in exports.iteritems():
            for i in range(8):
                if va - i in exp:
                    func_name = exp[va - i]
                    break
            if func_name != '':
                break
        return func_name

    def resolve_addr_by_func_name(self, func_name):
        """
        Reverse resolve, get the address given the function name.

        Parameters:
          func_name : function name

        Returns: address for function name
        """
        exports = self.get_exports()
        addr = 0
        for dll, exp in exports.iteritems():
            try:
                addr = (addr for addr, name in exp.items()
                        if name == func_name).next()
            except StopIteration:
                continue
            if addr != 0:
                break
        return addr

    def get_allocation_base(self, va):
        """
        Try to find the base address given a virtual address.

        Parameters:
          va : virtual address

        Returns: allocation base virtual address
        """
        mbi = self.process.mquery(va)
        return mbi.AllocationBase

    def find_contiguous_memory_size(self, va):
        """
        Looking for contiguous memory regions.

        Parameters:
          va : virtual address

        Returns: beginning virtual address and size
        """
        begin_va = self.get_allocation_base(va)
        va = begin_va
        size = 0
        if begin_va > 0:
            while True:
                mbi = self.process.mquery(va)
                if not mbi.is_commited():
                    break
                if mbi.AllocationBase != begin_va:
                    break
                size += mbi.RegionSize
                va += mbi.RegionSize
        return begin_va, size

    def get_process_region_bytes(self, va):
        """
        Get the bytes from a memory region.

        Parameters:
          va : virtual address

        Returns: memory region bytes
        """
        begin_va = self.get_allocation_base(va)
        va = begin_va
        bytes = ''

        if begin_va > 0:
            while True:
                mbi = self.process.mquery(va)
                if mbi.AllocationBase != begin_va:
                    break
                elif mbi.is_commited():
                    bytes += self.process.read(va, mbi.RegionSize)
                elif mbi.is_reserved():
                    bytes += '\0' * mbi.RegionSize
                elif mbi.is_free():
                    break
                va += mbi.RegionSize

        return bytes

    def get_exports(self):
        """
        Get's all module exports.

        Returns: module exports
        """
        if not self.module_exports:
            self.process.scan_modules()
            self.module_exports = {}
            for module in self.process.iter_modules():
                exports = self.get_module_exports(module)
                name = module.get_name()
                self.module_exports[name] = exports
        else:
            self.process.scan_modules()
            for module in self.process.iter_modules():
                name = module.get_name()
                if name not in self.module_exports:
                    exports = self.get_module_exports(module)
                    self.module_exports[name] = exports
        return self.module_exports

    def get_module_exports(self, module):
        """
        Walks the export table using a vivisect PE object.

        Parameters:
          module : winappdbg module object

        Returns: all modules exports
        """
        process = self.process
        exports = {}
        read_failed = False

        # Image base
        base = module.get_base()
        size = module.get_size()

        try:
            dll_mem = self.process.read(base, size)
        except:
            read_failed = True

        if not read_failed:
            memobj = envi.memory.MemoryObject()
            memobj.addMemoryMap(base, envi.memory.MM_RWX, "", dll_mem)
            pe = PE.peFromMemoryObject(memobj, base)
        else:
            pe = PE.peFromFileName(module.get_filename())

        for rva, _, func_name in pe.getExports():
            exports[base + rva] = func_name


        return exports


class ModuleUtils:
    """
    Some module specific functions
    """

    def __init__(self, dbg, pi, ignore_base_addrs=[]):
        """
        Initializes the ModuleUtils class.

        Parameters:
          dbg : DebugUtils object
          pi : ProcessUtils object 
          ignore_base_addrs : modules to ignore
        """
        self._module_mbis = {}
        self.dbg = dbg
        self.pi = pi
        self.process = self.dbg.process
        if type(ignore_base_addrs) in (int, long):
            ignore_base_addrs = [ignore_base_addrs]
        self.ignore_base_addrs = ignore_base_addrs

    def get_module_mbis(self):
        """
        Gets the executable sections of a module, but ignores a module within a given ignore_base_addrs.

        Returns: dictionary of loaded module mbis
        """
        self.process.scan_modules()
        if self.process.get_module_count() != len(self._module_mbis):
            mem_map = self.process.get_memory_map()
            for module in self.process.iter_modules():
                mod_beg = module.get_base()
                if mod_beg not in self._module_mbis.keys():
                    self._module_mbis[mod_beg] = []
                    mod_end = mod_beg + module.get_size()
                    for mbi in mem_map:
                        if mod_beg <= mbi.BaseAddress < mod_end:
                            self._module_mbis[mod_beg].append(
                                (mbi.BaseAddress, mbi.BaseAddress + mbi.RegionSize, mbi.is_executable()))
        return self._module_mbis

    def get_module_exec_sections(self, use_ignore_list=True):
        """
        Get memory regions within a module marked executable.

        Parameters:
          use_ignore_list : bool to use the ignore list

        Returns: executable mbis
        """
        exec_sections = []
        # if not self._module_mbis:
        self.get_module_mbis()
        for mod_beg, mbis in self._module_mbis.iteritems():
            if use_ignore_list and mod_beg in self.ignore_base_addrs:
                continue
            for start, end, executable in mbis:
                if executable:
                    exec_sections.append((start, end))
        return exec_sections

    def get_module_exec_section_bases(self, use_ignore_list=True):
        """
        Get memory region base addresses within modules marked executable.

        Returns: the base addresses for each executable mbi
        """
        exec_sections = self.get_module_exec_sections(use_ignore_list)
        return [base[0] for base in exec_sections]

    def exec_module_func(self, va):
        """
        Checks if the VA is in the range of a library function, if it is, execute the library function and return to the caller.

        Parameters:
          va : virtual address
        """
        lib_addrs = self.get_module_exec_sections()
        for start, end in lib_addrs:
            if start <= va < end:
                self.dbg.step_out()
                break
        if 'LoadLibrary' in self.pi.resolve_func_by_addr(va):
            self.get_module_mbis()

    def module_step_out(self):
        """
        Steps out of current executable memory region.
        """
        out = []
        pc = self.dbg.get_pc()
        for mbi in self.process.get_memory_map():
            if not (mbi.BaseAddress <= pc < mbi.BaseAddress + mbi.RegionSize):
                out.append(mbi.BaseAddress)
        self.dbg.set_mem_breakpoint(out)


"""
  Custom exceptions
"""


class AccessViolationException(Exception):
    """
    Access violation exceptions
    """

    def __init__(self, va):
        """
        Handles access violation exceptions. 

        Parameters:
          va : virtual address of access violation
        """
        self.va = va

    def __str__(self):
        return "Access Violation occurred at virtual address: 0x%x" % (self.va)


class SecondChanceException(Exception):
    """
    Second chance exceptions
    """
    pass


class ControlBreakException(Exception):
    """
    Ctrl+Break received
    """
    pass


"""
  Exception handlers
"""


class BreakpointExceptionHandler(pykd.eventHandler):
    """
    Set breakpoints and break when one is hit.
    """

    def __init__(self, addrs):
        """
        Initializes the breakpoint exception handler.

        Parameters:
          addrs : list of virtual addresses to set breakpoints
        """
        pykd.eventHandler.__init__(self)
        self.pykd_version = get_pykd_version()
        self.bp_hit_addr = None
        self.except_addr = None
        self.ctrlbr = False
        self.av = False
        if type(addrs) in (int, long):
            addrs = [addrs]
        self.bp_ids = {}
        self.set_breakpoints(addrs)

    def __del__(self):
        self.remove_breakpoints()

    def set_breakpoints(self, addrs):
        """
        Sets breakpoints.

        Parameters:
          addrs : list of virtual addresses to set breakpoints
        """
        for addr in list(set(addrs)):
            bp = pykd.setBp(addr)
            if self.pykd_version == PYKD3:
                bp_id = bp.getId()
                self.bp_ids[bp_id] = bp
            else:
                self.bp_ids[bp] = addr

    def remove_breakpoints(self):
        """
        Removes all breakpoints that were set.
        """
        for bp_id in self.bp_ids.keys():
            if self.pykd_version == PYKD3:
                self.bp_ids[bp_id].remove()
            else:
                pykd.removeBp(bp_id)
            del self.bp_ids[bp_id]

    def onBreakpoint(self, bp_id):
        """
        Handles onBreakpoint event.

        Parameters:
          bp_id : breakpoint id

        Returns: pykd Break event
        """
        if bp_id in self.bp_ids.keys():
            if self.pykd_version == PYKD3:
                self.bp_hit_addr = self.bp_ids[bp_id].getOffset()
            else:
                self.bp_hit_addr = self.bp_ids[bp_id]
        self.remove_breakpoints()

        return pykd.eventResult.Break

    # Exception callback
    def onException(self, exceptInfo):
        """
        Handles exceptions.

        Parameters:
          exceptInfo : pykd ExceptInfo object

        Returns: pykd event
        """
        ret = pykd.eventResult.NoChange
        except_code = 0
        cexcept_addr = 0
        first_chance = False

        if self.pykd_version == PYKD3:
            except_code = exceptInfo.exceptionCode
            cexcept_addr = exceptInfo.exceptionAddress
            first_chance = exceptInfo.firstChance
        else:
            except_code = exceptInfo.ExceptionCode
            cexcept_addr = exceptInfo.ExceptionAddress
            first_chance = exceptInfo.FirstChance

        if except_code == winappdbg.win32.kernel32.STATUS_BREAKPOINT:
            self.ctrlbr = True
            self.remove_breakpoints()
            ret = pykd.eventResult.Break
        elif except_code == winappdbg.win32.kernel32.STATUS_ACCESS_VIOLATION:
            self.av = True
            self.except_addr = cexcept_addr
            self.remove_breakpoints()
            ret = pykd.eventResult.Break

        return ret


class PageGuardExceptionHandler(pykd.eventHandler):
    """
    PAGE_GUARD exception handler for memory breakpoints
    """

    def __init__(self, process, addrs):
        """
        Initializes the page guard exception handler.

        Parameters:
          process : winappdbg process object 
          addrs : list of addresses to set page guard protection
        """
        pykd.eventHandler.__init__(self)
        self.pykd_version = get_pykd_version()
        self.process = process
        self.membps = []
        if type(addrs) in (int, long):
            addrs = [addrs]
        self.change_protect(addrs)
        self.except_addr = None
        self.bp_hit = False
        self.ctrlbr = False
        self.av = False
        self.mem_access = False
        self.second_chance = False

    def change_protect(self, addrs):
        """
        Sets the PAGE_GUARD protection on all addrs.

        Parameters:
          addrs : list of addresses to set the PAGE_GUARD protection
        """
        for addr in addrs:
            membp = {}
            mbi = self.process.mquery(addr)
            if mbi.is_executable() and not mbi.is_mapped():
                membp['size'] = mbi.RegionSize
                membp['base_addr'] = mbi.BaseAddress
                membp['end_addr'] = mbi.BaseAddress + mbi.RegionSize
                membp['old_protect'] = self.process.mprotect(membp['base_addr'], membp['size'],
                                                             mbi.Protect | winappdbg.win32.PAGE_GUARD)
                self.membps.append(membp)

    def reset_protect(self):
        """
        Removes the PAGE_GUARD protection on all specified addrs.
        """
        for membp in self.membps:
            mbi = self.process.mquery(membp['base_addr'])
            if not mbi.is_free():
                self.process.mprotect(membp['base_addr'], membp['size'], membp['old_protect'])

    # Exception callback
    def onException(self, exceptInfo):
        """
        Handles exceptions.

        Parameters:
          exceptInfo : pykd ExceptInfo object

        Returns: pykd event
        """
        ret = pykd.eventResult.NoChange
        except_code = 0
        cexcept_addr = 0
        first_chance = False
        self.mem_access = False

        if self.pykd_version == PYKD3:
            except_code = exceptInfo.exceptionCode
            cexcept_addr = exceptInfo.exceptionAddress
            first_chance = exceptInfo.firstChance
        else:
            except_code = exceptInfo.ExceptionCode
            cexcept_addr = exceptInfo.ExceptionAddress
            first_chance = exceptInfo.FirstChance

        # Handle guard page exceptions and check if the execution address is in
        # our range, so we don't deal with memory access breaks
        if except_code == winappdbg.win32.kernel32.STATUS_GUARD_PAGE_VIOLATION:
            ret = pykd.eventResult.Break
            self.mem_access = True
            self.except_addr = cexcept_addr
            self.reset_protect()
            for membp in self.membps:
                if membp['base_addr'] <= cexcept_addr < membp['end_addr']:
                    self.bp_hit = True
                    self.mem_access = False
                    break

        # If Ctrl+Break was issued, reset protections and prepare to exit
        elif except_code == winappdbg.win32.kernel32.STATUS_BREAKPOINT:
            self.bp_hit = True
            self.ctrlbr = True
            self.reset_protect()
            ret = pykd.eventResult.Break
        # Not dealing with second chance exceptions
        elif not first_chance:
            self.bp_hit = True
            self.second_chance = True
            self.reset_protect()
            ret = pykd.eventResult.Break
        elif except_code == winappdbg.win32.kernel32.STATUS_ACCESS_VIOLATION:
            self.bp_hit = True
            self.av = True
            self.except_addr = cexcept_addr
            self.reset_protect()
            ret = pykd.eventResult.Break

        return ret


class AccessViolationExceptionHandler(pykd.eventHandler):
    """
    Access violation exception handler
    """

    def __init__(self, process=None, addrs=[]):
        """
        Initializes access violation exception handler.

        Parameters:
          process : (optional) winappdbg process object 
          addrs : list of virtual addresses
        """
        pykd.eventHandler.__init__(self)
        self.pykd_version = get_pykd_version()
        self.process = process
        self.membps = []
        if type(addrs) in (int, long):
            addrs = [addrs]
        self.change_protect(addrs)
        self.except_addr = None
        self.bp_hit = False
        self.av = False
        self.ctrlbr = False
        self.second_chance = False

    def change_protect(self, addrs):
        """
        Removes the executable protection on all addrs.

        Parameters:
          addrs : list of virutal addresses
        """
        for addr in addrs:
            membp = {}
            mbi = self.process.mquery(addr)
            if mbi.is_executable():
                membp['size'] = mbi.RegionSize
                membp['base_addr'] = mbi.BaseAddress
                membp['end_addr'] = mbi.BaseAddress + mbi.RegionSize
                membp['old_protect'] = self.process.mprotect(membp['base_addr'], membp['size'],
                                                             winappdbg.win32.PAGE_READWRITE)
                self.membps.append(membp)

    def reset_protect(self):
        """
        Resets the original protection on all specified addrs.
        """
        for membp in self.membps:
            mbi = self.process.mquery(membp['base_addr'])
            if not mbi.is_free():
                self.process.mprotect(membp['base_addr'], membp['size'], membp['old_protect'])

    # Exception callback
    def onException(self, exceptInfo):
        """
        Handles exceptions.

        Parameters:
          exceptInfo : pykd ExceptInfo object

        Returns: pykd event
        """
        ret = pykd.eventResult.NoChange
        except_code = 0
        cexcept_addr = 0
        first_chance = False

        if self.pykd_version == PYKD3:
            except_code = exceptInfo.exceptionCode
            cexcept_addr = exceptInfo.exceptionAddress
            first_chance = exceptInfo.firstChance
        else:
            except_code = exceptInfo.ExceptionCode
            cexcept_addr = exceptInfo.ExceptionAddress
            first_chance = exceptInfo.FirstChance

        # Handle acces violation errors
        if except_code == winappdbg.win32.kernel32.STATUS_ACCESS_VIOLATION:
            ret = pykd.eventResult.Break
            self.reset_protect()
            self.except_addr = cexcept_addr
            for membp in self.membps:
                if membp['base_addr'] <= cexcept_addr < membp['end_addr']:
                    self.bp_hit = True
                    break
            if not self.bp_hit:
                self.av = True

        # If Ctrl+Break was issued, reset protections and prepare to exit
        elif except_code == winappdbg.win32.kernel32.STATUS_BREAKPOINT:
            self.bp_hit = True
            self.ctrlbr = True
            self.reset_protect()
            ret = pykd.eventResult.Break
        # Not dealing with second chance exceptions
        elif not first_chance:
            self.bp_hit = True
            self.second_chance = True
            self.reset_protect()
            ret = pykd.eventResult.Break

        return ret