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
# The membreak plugin is used to set breakpoints on an entire memory region.
# Memory breakpoints can be achieved in two primary ways: by adjusting the
# page guard protection or removing the execute protection. If any part of
# a memory region begins to execute, an exception is generated and handled
# by the plugin and the debugger regains control of the program. After
# a memory breakpoint is hit, the original memory protections are restored.
#
# The plugin will fail if VirtualProtect is called by the running program
# and changes the protection.
#
# If passed the -a flag, the membreak plugin will remove the execute
# protection and waits for an access violation. However, if the executable
# is running in an environment where DEP is disabled, this breakpoint type
# will fail. In this case, use the page guard breakpoint instead.
#
#  usage: !py membreak [-h] [-a] addr [addr ...]
#
#  positional arguments:
#    addr
#
#  optional arguments:
#    -h, --help            show this help message and exit
#    -a, --access-breakpoint
#                          Use access violation breakpoint instead guard page
#
# Multiple addresses can be specified. If more than one address is specified,
# the plugin will set multiple memory breakpoints. When one is hit, all the
# memory protections are restored.
#

import sys
import argparse
from flaredbg import flaredbg

def hexint(x):
    return int(x, 16)

class AddressParseAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)

def main():
    script_name = sys.argv[0].split('\\')[-1]
    parser = argparse.ArgumentParser(description='!py %s is used to create a memory breakpoint on memory region addresses' % script_name)
    parser.add_argument('-a', '--access-breakpoint', action="store_true", help="Use access violation breakpoint instead guard page")
    parser.add_argument('addr', nargs='+', type=hexint, action=AddressParseAction)
    args = parser.parse_args()

    dbg = flaredbg.DebugUtils()

    print " Running until memory breakpoint hit."
    if args.access_breakpoint:
        hit_addr = dbg.set_access_breakpoint(args.addr)
    else:
        hit_addr = dbg.set_mem_breakpoint(args.addr)
    print " Memory breakpoint hit!\n  0x%x" % (hit_addr)

if __name__ == "__main__":
    main()
