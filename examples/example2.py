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

########################################################################
#
# sogu strings decoder. Written for: 41d059f059795e91137fd411b5f4d74d
#
# 1) Run the malware and attach to the malware with windbg.
# 2) Run the example2.py decoder script.
# 3) Retrieve the output ida_comments.py script and run it in IDA to annotate the decoded strings.
#
########################################################################

from flaredbg import flaredbg, utils

def main():
    # Function virtual address for the string decoder function
    fva = 0x10002F6C
    fva_end = 0x10003071

    dbg = flaredbg.DebugUtils()

    # Use get call list to retrieve two push args and three register args
    call_list = dbg.get_call_list(fva, 2, ['eax', 'ecx', 'edi'])

    # Create a list of output decoded strings for an IDA python script
    out_list = []

    # Iterate through all the times the fva was called
    for fromva, args in call_list:
        # Allocate some memory for a stack variable that will receive the output
        str_buf = dbg.malloc(0x20)
        # Update ecx with the new memory
        dbg.set_reg_arg(args, 'ecx', str_buf)

        try:
            # Make the call, and specify the last address of the function, this makes the function run much faster
            # as it will run until a breakpoint instead of single stepping a function looking for a return.
            out_buf = dbg.call(fva, args, fromva, tova=fva_end)
            # Read the string output
            str_va = dbg.read_pointer(out_buf)
            out_str = dbg.read_string(str_va)
        except flaredbg.AccessViolationException as e:
            print "Access violation at: 0x%x" % e.va
            out_str = ''

        # Print out the result
        print hex(fromva), repr(out_str)
        # Free the memory
        dbg.free(str_buf)

        # Append the result to the IDA comments list
        out_list.append((fromva, out_str))

    # Generate an IDA script and write it out
    ida_script = utils.generate_ida_comments(out_list, True)
    open('C:\\ida_comments.py', 'wb').write(ida_script)

if __name__ == '__main__':
    main()