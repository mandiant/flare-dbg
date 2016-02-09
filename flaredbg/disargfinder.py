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

import envi

def find_push_args(vw, dis, num_push_args):
    """
    Try to find push instructions with immediate values without emulation, ignoring program flow.

    Parameters:
      dis : list of opcodes from vivisect
      num_push_args : number of push arguments to search for

    Returns: list of push values found from disassembly
    """
    push_args = []
    ignore_me = False
    # Using default value of 1, for reasons
    DEFAULT = 1
    for i, op in enumerate(reversed(dis)):
        if len(push_args) >= num_push_args:
            break
        if op.mnem == 'pop':
            ignore_me = True
        elif op.mnem == 'push':
            if not ignore_me:
                value = DEFAULT
                opnds = op.getOperands()
                if len(opnds) > 0:
                    opnd = opnds[0]
                    if opnd.isReg():
                        recursive_reg_name = opnd.repr(op)
                        recursive_find = find_reg_args(vw, dis[i:], [recursive_reg_name])
                        value = DEFAULT
                        if recursive_find:
                            value = recursive_find[0][recursive_reg_name]
                    elif opnd.isImmed():
                        value = opnd.getOperValue(op)
                push_args.append(value)
            else:
                ignore_me = False
        elif op.mnem == 'mov':
            opnds = op.getOperands()
            if opnds:
                opnd0 = opnds[0]
                if opnd0.isDeref() and hasattr(opnd0, 'reg'):
                    # todo figure this out for 64-bit
                    if opnd0.reg in (envi.archs.i386.REG_ESP, envi.archs.amd64.REG_RSP):
                        if opnd0.disp in range(0, -num_push_args * vw.psize, -vw.psize):
                            opnd1 = opnds[1]
                            value = DEFAULT
                            if opnd1.isImmed():
                                value = opnd1.getOperValue(op)
                            if len(push_args) <= opnd0.disp / vw.psize:
                                push_args.append(value)
                            else:
                                push_args[opnd0.disp / vw.psize] = value
    return push_args

def find_reg_args(vw, dis, regs):
    """
    Try to find immediate register values without emulation, ignoring program flow.

    Parameters:
      dis : list of opcodes from vivisect
      regs : list of register names

    Returns: list of register values found from disassembly
    """
    lregs = list(regs)
    reg_args = []
    find_push = False
    # Using default value of 1, for reasons
    DEFAULT = 1
    for i, op in enumerate(reversed(dis)):
        # Handle direct mov
        if op.mnem == 'mov':
            opnds = op.getOperands()
            if len(opnds) > 1:
                opnd0 = opnds[0]
                if opnd0.isReg():
                    for reg_name in lregs:
                        if opnd0.repr(op) == reg_name:
                            opnd1 = opnds[1]
                            if opnd1.isImmed():
                                value = opnd1.getOperValue(op)
                            elif opnd1.isReg():
                                recursive_reg_name = opnd1.repr(op)
                                recursive_find = find_reg_args(vw, dis[i:], [recursive_reg_name])
                                value = DEFAULT
                                if recursive_find:
                                    value = recursive_find[0][recursive_reg_name]
                            else:
                                # TODO: Handle regs being set by something
                                # other than an immediate value
                                value = DEFAULT
                            reg_args.append({reg_name: value})
                            lregs.remove(reg_name)
                            break
        elif op.mnem == 'lea':
            # Not sure how to handle this right now, maybe if one of the
            # regs wasn't found, just set it to DEFAULT?
            opnds = op.getOperands()
            opnd0 = opnds[0]
            if opnd0.isReg():
                for reg_name in lregs:
                    if opnd0.repr(op) == reg_name:
                        opnd1 = opnds[1]
                        if 'RegMemOper' in opnd1.__class__.__name__:
                            value = DEFAULT
                            lea_reg_name = opnd1._dis_regctx.getRegisterName(opnd1.reg)
                            if hasattr(opnd1, 'disp'):
                                recursive_find = find_reg_args(vw, dis[i:], [lea_reg_name])
                                if recursive_find:
                                    value = recursive_find[0][lea_reg_name] + opnd1.disp
                            reg_args.append({reg_name: value})
                            lregs.remove(reg_name)
                            break
                        else:
                            reg_args.append({reg_name: DEFAULT})
                            lregs.remove(reg_name)
                            break
        # Handle zeroing xor
        elif op.mnem == 'xor':
            opnds = op.getOperands()
            reg_name = opnds[0].repr(op)
            if opnds[0].isReg() and reg_name in lregs:
                if opnds[1].isReg():
                    if opnds[0].reg == opnds[1].reg:
                        reg_args.append({reg_name: 0})
                        lregs.remove(reg_name)
        # Handle push/pop
        elif op.mnem == 'pop':
            opnds = op.getOperands()
            if len(opnds) > 0:
                opnd0 = opnds[0]
                if opnd0.isReg():
                    for reg_name in lregs:
                        if opnd0.repr(op) == reg_name:
                            find_push = reg_name
                            break
        elif op.mnem == 'push' and find_push:
            opnds = op.getOperands()
            if len(opnds) > 0:
                opnd0 = opnds[0]
                if opnd0.isImmed():
                    value = opnd0.getOperValue(op)
                elif opnd0.isReg():
                    recursive_reg_name = opnd0.repr(op)
                    recursive_find = find_reg_args(vw, dis[i:], [recursive_reg_name])
                    value = DEFAULT
                    if recursive_find:
                        value = recursive_find[0][recursive_reg_name]
                else:
                    # TODO: Handle this case
                    value = DEFAULT
                if find_push in lregs:
                    reg_args.append({find_push: value})
                    lregs.remove(find_push)
            find_push = False
        if len(lregs) == 0:
            break
    return reg_args

def find_args(vw, fromva, num_push_args, regs=[]):
    """
    Naively try to find arguments without emulation, using only the disassembly.

    Parameters:
      fromva : virtual address that contains the call
      num_push_args : number of push arguemnts
      regs : list of register names

    Returns: argument list found from disassembly
    """
    arg_list = []
    if vw is not None:
        fva = vw.getFunction(fromva)
        va = fva
        dis = []
        while va < fromva:
            try:
                op = vw.parseOpcode(va)
            except envi.InvalidInstruction as e:
                print str( e )
                break
            dis.append(op)
            va += op.size
        push_args = find_push_args(vw, dis, num_push_args)
        reg_args = find_reg_args(vw, dis, regs)

        args = reg_args + push_args
        arg_list.append(args)
    else:
        print " [-] Please generate a vivisect workspace first!"

    return arg_list