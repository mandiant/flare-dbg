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
# The importfind plugin searches for references to runtime imported functions.
# The plugin iterates all loaded DLLs and parses their export tables to find the in-memory
# virtual address for each named function. The plugin will then search for references to
# those addresses within a memory region.
#
# For example, if a program imported a function using:
# call GetProcAddress(esi, 'WriteProcessMemory');
# mov dword_403220, eax
#
# This global dword may be called later:
# call dword_403220
#
# The importfind plugin will rename the dword_403220 to WriteProcessMemory
#
#  usage: !py importfind [-h] [-o SCRIPT_PATH] addr
#
#  positional arguments:
#    addr                  Address in a memory region
#
#  optional arguments:
#    -h, --help            show this help message and exit
#    -o SCRIPT_PATH, --script-path SCRIPT_PATH
#                          Output IDAPython script full path
#
# The output script will be an IDAPython script which can be run in IDA to automatically
# rename global variables that contain the runtime imported functions.
#

import sys
import argparse
from flaredbg import flaredbg, utils

def hexint(x):
    return int(x, 16)

def main():
    script_name = sys.argv[0].split('\\')[-1]
    parser = argparse.ArgumentParser(description='!py %s is used to find all library function addresses in a memory region' % script_name)
    parser.add_argument('-o', '--script-path', help='Output IDAPython script full path')
    parser.add_argument('addr', type=hexint, help='Address in a memory region')
    args = parser.parse_args()
    
    if args.addr and args.script_path:
        pu = flaredbg.ProcessUtils()

        base_addr = pu.get_allocation_base(args.addr)
        imports = pu.find_imports(base_addr)

        if imports:
            name_list = []
            for va, func in imports.iteritems():
                if 'func_name' in func:
                    name_list.append((va, func['func_name']))
            idascript = utils.generate_ida_names(name_list)
            open(args.script_path, 'wb').write(idascript)
            print ' [+] Successfully wrote IDA Python script to %s' % args.script_path
        else:
            print ' [-] Failed to find library function addresses'

if __name__ == '__main__':
    main()
