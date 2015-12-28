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

from flaredbg import flaredbg, utils

def main():
    # Function virtual address for the string decoder function
    fva = 0x401000

    dbg = flaredbg.DebugUtils()

    # Get all the locations the fva function was called from as well as the arguments
    # get_call_list accepts the number of push arguments and the required registers
    # The function of interest in this example only accepts push arguments
    call_list = dbg.get_call_list(fva, 3)

    # Create a list of output decoded strings for an IDA python script
    out_list = []

    # Iterate through all the times the fva was called
    for fromva, args in call_list:
        # Allocate some memory for the output string and the output string size
        str_va = dbg.malloc(args[2])
        args[1] = str_va

        try:
            # Make the call!
            dbg.call(fva, args, fromva)
            # Read the string output
            out_str = dbg.read_string(str_va)
        except flaredbg.AccessViolationException as e:
            print "Access violation at: 0x%x" % e.va
            out_str = ''

        # Print out the result
        print hex(fromva), out_str
        # Free the memory
        dbg.free(str_va)

        # arg 0 contains the "unknown" bytes offset, and out contains the decoded string
        out_list.append((args[0], out_str))

    # Generate an IDA script and write it out
    ida_script = utils.generate_ida_comments(out_list, True)
    open('C:\\ida_comments.py', 'wb').write(ida_script)

if __name__ == '__main__':
    main()
