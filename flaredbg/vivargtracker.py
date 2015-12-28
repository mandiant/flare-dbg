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

# Modified / standalone version of https://github.com/fireeye/flare-ida/blob/master/python/flare/argtracker.py
# Can be used without IDA

import os
import sys
import copy
import struct
import logging
import binascii

import vivisect
import vivisect.impemu as viv_imp
import vivisect.impemu.monitor as viv_imp_monitor
from visgraph import pathcore as vg_path


BADADDR = -1

########################################################################
#
#
########################################################################

class RegMonitor(viv_imp_monitor.EmulationMonitor):
    '''
    This tracks all register changes, even if it's not currently an interesting reg
    because we need to trace register changes backwards.
    '''

    def __init__(self, regs):
        viv_imp_monitor.EmulationMonitor.__init__(self)
        self.logger = logging.getLogger('argracker.RegMonitor')
        self.regs = regs[:]
        self.reg_map = {}

    def prehook(self, emu, op, starteip):
        try:
            #self.logger.debug('prehook:  0x%08x', starteip)
            self.cachedRegs = emu.getRegisters()
            self.startEip = starteip
        except Exception, err:
            self.logger.exception('Error in prehook: %s', str(err))

    def posthook(self, emu, op, endeip):
        try:
            #self.logger.debug('posthook: 0x%08x', endeip)
            curRegs = emu.getRegisters()
            curDict = {}
            for name, val in curRegs.items():
                if (self.cachedRegs[name] != val):
                    curDict[name] = val
            if len(curDict) != 0:
                self.reg_map[self.startEip] = curDict
        except Exception, err:
            self.logger.exception('Error in posthook: %s', str(err))


########################################################################
#
#
########################################################################

#maps a va to the vg_path node that contains it in an emu run
def build_emu_va_map(node, **kwargs):
    res = kwargs.get('res')
    emu = kwargs.get('emu')
    logtype = kwargs.get('logtype')
    if (res is None) or (emu is None) or (logtype is None):
        return
    #for va in vg_path.getNodeProp(node, 'valist'):
    #    res[va] = node
    #for pc, va, bytes in vg_path.getNodeProp(node, 'writelog'):
    for entry in vg_path.getNodeProp(node, logtype):
        pc, va, bytes = entry
        res[pc] = entry


def formatWriteLogEntry(entry):
    pc, va, bytes = entry
    return '0x%08x: 0x%08x: %s' % (pc, va, binascii.hexlify(bytes))

def transformWriteLogEntry(entry, bigend=False):
    '''
    Tranforms a writelog entry to a (pc, value) tuple
    '''
    pc, va, bytes = entry
    blen = len(bytes)
    if blen == 1:
        return (pc, struct.unpack_from('<B', bytes)[0])
    elif blen == 2:
        return (pc, struct.unpack_from('<H', bytes)[0])
    elif blen == 4:
        return (pc, struct.unpack_from('<I', bytes)[0])
    elif blen == 8:
        return (pc, struct.unpack_from('<Q', bytes)[0])
    elif blen == 16:
        t0,t1 =  struct.unpack_from('<QQ', bytes)[0]
        return (pc, (t1<<64) | t0)
    else:
        raise RuntimeError('Unexpected len of writelog bytes: %d' % blen)

class TrackerState(object):
    def __init__(self, tracker, baseEntry, num, regs):
        '''
        desiredState: list of stackArgNums and register names
        '''
        self.tracker = tracker
        self.baseEntry = baseEntry
        self.num = num
        self.regs = regs[:]
        self.ptrsize = tracker.ptrsize
        self.resultArgs = {}

        #stackArgLocs: pre-calculated locations we're looking for for stack writes
        self.stackArgLocs = []

        #tempMapping: used to follow data movement backwards. if a value we're interested
        # in is loaded in another register or a memory location, maps the current
        self.tempMapping = {}

        #desiredState: list of stackArgNums and register names
        self.desiredState = []

        self.setDesiredState(baseEntry, num, regs)
        self.setStackArgLocs(baseEntry, num, regs)

    def copy(self):
        cp = TrackerState(self.tracker, self.baseEntry, self.num, self.regs)
        cp.resultArgs = copy.deepcopy(self.resultArgs)
        cp.tempMapping = copy.deepcopy(self.tempMapping)
        cp.desiredState = copy.deepcopy(self.desiredState)
        return cp

    def __str__(self):
        info = '\n'.join([ '%s: %s,' % (self.getArgNameRep(k), repr(self.resultArgs.get(k))) for k in self.desiredState])
        return info

    def processWriteLog(self, tracker, cVa):
        wlogEntry = tracker.va_write_map.get(cVa, None)
        if (wlogEntry is None):
            return
        pc, writeVa, bytes = wlogEntry
        if (writeVa in self.stackArgLocs) and (self.getStackArgNum(writeVa) not in self.resultArgs.keys()):
            #it's a stack arg value
            pc, value = transformWriteLogEntry(wlogEntry)
            #self.tracker.logger.debug('writelog 0x%08x: Found stack arg %d: 0x%08x', pc, self.getStackArgNum(writeVa), value)
            self.saveResult(writeVa, pc, value)
            return

        if writeVa not in self.tempMapping.keys():
            #self.tracker.logger.debug('writelog 0x%08x: not interesting', pc)
            return

        #argName: the actual value we're tracing back
        argName = self.tempMapping.pop(writeVa)
        pc, value = transformWriteLogEntry(wlogEntry)

        #we found a temp value tracing backwards, but need to determine if it's a constant
        # or if we need to continue tracing backwards. basically as long as it's not
        # a register, we stop?
        #mnem = idc.GetMnem(pc)
        op = self.tracker.vw.parseOpcode(pc)
        mnem = op.mnem
        srcOpIdx = 0
        if mnem.startswith('push'):
            srcOpIdx = 0
        elif mnem.startswith('mov'):
            srcOpIdx = 1
        else:
            #TODO: any other data movement instructions need to be traced rahter
            # than using the observed write log value?
            #self.tracker.logger.debug('writelog 0x%08x: found (default): 0x%08x', pc, value)
            self.saveResult(argName, pc, value)
            return

        #process data movements instructions:
        #optype = idc.GetOpType(pc, srcOpIdx)
        opnds = op.getOperands()
        #if optype == idc.o_reg:
        if opnds[srcOpIdx].isReg():
            #need to trace the new reg now
            #newReg = idc.GetOpnd(pc, srcOpIdx)
            newReg = repr(opnds[srcOpIdx])
            #self.tracker.logger.debug('writelog 0x%08x tracing: (%s): %s', pc, self.getArgNameRep(argName), newReg)
            self.tempMapping[newReg] = argName
        else:
            #not a register, so currently assuming we can use the stored value
            #self.tracker.logger.debug('writelog 0x%08x: found (non-reg): 0x%08x', pc, value)
            self.saveResult(argName, pc, value)

    def getArgNameRep(self, argName):
        if isinstance(argName, int) or isinstance(argName, long):
            return '0x%08x' % argName
        return argName

    def getStackArgNum(self, writeVa):
        return (writeVa - self.startSp)/self.ptrsize

    def saveResult(self, argName, pc, value):
        '''
        Saves a tuple (pc, value) to the found argument.
        Assumes if argName is an integer, it's the address of an expected stack argument.
        If argName is a string, it's a register name for an expected argument.
        '''
        if isinstance(argName, int) or isinstance(argName, long) :
            #argNum = (wlogEntry[1] - self.startSp)/tracker.ptrsize
            argNum = self.getStackArgNum(argName)
            self.resultArgs[argNum] = (pc, value)
        elif isinstance(argName, str):
            self.resultArgs[argName] = (pc, value)
        else:
            raise RuntimeError('Unknown argName type: %s' % type(argName))

    def processRegMon(self, tracker, cVa):
        if tracker.regMon is None:
            #tracker.logger.debug('regmon: regMon is empty')
            return
        regMods = tracker.regMon.reg_map.get(cVa)
        if regMods is None:
            #tracker.logger.debug('regmon 0x%08x: no entry in reg_map', cVa)
            return
        #figure out if one of the monitored regs is modified in this instruction
        # and if has not already been stored -> just want the first reg value
        regMods = self.tracker.regMon.reg_map[cVa]
        #self.tracker.logger.debug('regmon 0x%08x: examining %d items: %r', cVa, len(regMods), regMods)
        for reg in regMods:
            interesting1 = (reg in self.regs) and (reg not in self.resultArgs.keys())
            interesting2 = (reg in self.tempMapping.keys())
            if (not interesting1) and (not interesting2):
                #modified reg isn't interesting: either a function arg or a temp traced value
                #self.tracker.logger.debug('regmon 0x%08x: not interesting: %s', cVa, reg)
                continue
            #mnem = idc.GetMnem(cVa)
            op = self.tracker.vw.parseOpcode(cVa)
            mnem = op.mnem
            argName = reg
            if interesting1:
                self.regs.remove(reg)
            if interesting2:
                argName = self.tempMapping.pop(reg)
            if mnem.startswith('pop'):
                #add the current stack read address to the temporary tracking
                rlogEntry = tracker.va_read_map.get(cVa, None)
                if rlogEntry is None:
                    raise RuntimeError('readlog entry does not exist for a pop')
                pc, readVa, bytes = rlogEntry
                #self.tracker.logger.debug('regmon 0x%08x tracing (pop): %s (%s): 0x%x', cVa, argName, reg, readVa)
                self.tempMapping[readVa] = argName
            elif mnem.startswith('mov'):
                opnds = op.getOperands()
                #if idc.GetOpType(cVa, 1) == idc.o_reg:
                if opnds[1].isReg():
                    #change to track this reg backwards
                    #newReg = idc.GetOpnd(cVa, 1)
                    newReg = repr(opnds[1])
                    #self.tracker.logger.debug('regmon 0x%08x tracing (mov): %s (%s)', cVa, argName, newReg)
                    self.tempMapping[newReg] = argName
                else:
                    #not a register, use the modified result otherwise?
                    #self.tracker.logger.debug('regmon 0x%08x found (mov): %s (%s): 0x%x', cVa, argName, reg, regMods[reg])
                    self.saveResult(argName, cVa, regMods[reg])
            else:
                #TODO: any other data movement instructions that should be traced back?
                #self.tracker.logger.debug('regmon 0x%08x found (default): %s (%s): 0x%x', cVa, argName, reg, regMods[reg])
                self.saveResult(argName, cVa, regMods[reg])

    def setStackArgLocs(self, baseEntry, num, regs):
        self.startSp = baseEntry[1]
        # desiredSp: the stack write addressses that correspond to the arguments we want
        self.stackArgLocs = [self.startSp + self.ptrsize*(1+i) for i in range(num)]

    def setDesiredState(self, baseEntry, num, regs):
        desiredState = [(i+1) for i in range(num)]
        desiredState.extend(regs)
        self.desiredState = sorted(desiredState)

    def isComplete(self):
        if len(self.desiredState) == len(self.resultArgs):
            if self.desiredState == sorted(self.resultArgs.keys()):
                return True
            else:
                raise RuntimeError('Matching len of resultArgs, but not equal!')
        return False

# jayutils.py functions:

######################################################################
# visgraph traversal helpers
######################################################################

def path_dfs(node, func, **kwargs):
    todo = [node]
    while len(todo) != 0:
        #node is a tuple of (parent, child_list, prop_dict)
        cur = todo.pop(0)
        #insert children at start of queue
        blah = cur[1][:]
        blah.extend(todo)
        todo = blah
        func(cur, **kwargs)

def path_bfs(node, func, **kwargs):
    todo = [node]
    while len(todo) != 0:
        #node is a tuple of (parent, child_list, prop_dict)
        cur = todo.pop(0)
        #append children to end of queue
        todo.extend(cur[1])
        func(cur, **kwargs)

######################################################################
# vivisect
######################################################################

def loadWorkspace(filename, fast=False):
    logger = logging.getLogger('loadWorkspace')

    vw = vivisect.VivWorkspace()
    vivName = filename + '.viv'
    if os.path.exists(vivName):
        logger.info('Loading existing workspace %s', vivName)
        sys.stdout.flush()
        vw.loadWorkspace(vivName)
    else:
        logger.info('Loading file into vivisect: %s', filename)
        sys.stdout.flush()
        vw.loadFromFile(filename)
        if not fast:
            logger.info('Performing vivisect analysis now. This may take some time...')
            logger.info('#'*80)
            vw.analyze()
            logger.info('#'*80)
            logger.info('Analysis done. Continuing now')
        vw.saveWorkspace()
    logger.info('Caching vw workspace object in global variable now')
    return vw

def getAllXrefsTo(vw, va):
    #manually parse the preceding instruction & look to see if it can fall through to us
    #make a copy of the xrefs!!! or badness will ensue
    init = vw.getXrefsTo(va)[:]
    prev = vw.getPrevLocation(va)
    if prev is None:
        return init
    lva, lsize, ltype, linfo = prev
    if ltype != vivisect.const.LOC_OP:
        return init
    try:
        op = vw.parseOpcode(lva)
    except Exception as err:
        print 'Weird error while doing getAllXrefsTo: %s' % str(err)
        return init
    brlist = op.getBranches()
    for tova,bflags in brlist:
        if tova == va:
            init.append( (lva, tova, vivisect.const.REF_CODE, bflags) )
    return init

########################################################################
#
#
########################################################################

class ArgTracker(object):

    def __init__(self, vw, maxIters=1000):
        self.logger = logging.getLogger('argracker.ArgTracker')
        self.logger.debug('Starting up here')
        self.vw = vw
        self.lastFunc = 0
        self.va_write_map = None
        self.ptrsize = self.vw.psize
        self.queue = []
        self.maxIters = maxIters

    def printWriteLog(self, wlog):
        for ent in wlog:
            self.logger.debug(formatWriteLogEntry(ent))

    def isCargsComplete(self, cargs, num, regs):
        return all([cargs.has_key(i+1) for i in range(num)]) and all([cargs.has_key(i) for i in regs])


    def getPushArgs(self, va, num, regs=None):
        '''
        num -> first arg is 1, 2nd is 2, ...

        Returns a list of dicts whose key is the arg number (starting at 1, 2.. num)
        Each dict for a stack argument is a write log tuple (pc, va bytes)
        Each dict for a registry is a tuple (pc, value)

        '''
        if regs is None:
            regs = []
        count = 0
        touched = []

        #func = self.vw.getFunction(va)
        #if func is None:
        #    self.logger.error('Could not get function start from vw 0x%08x -> has analysis been done???', va)
        #    return []
        #funcStart = idc.GetFunctionAttr(va, idc.FUNCATTR_START)
        funcStart = self.vw.getFunction(va)
        #if func != funcStart:
        #    self.logger.error('IDA & vivisect disagree over function start. Needs to be addressed before process')
        #    self.logger.error(' IDA: 0x%08x. vivisect: 0x%08x', funcStart, func)
        #    return []
        #map a every (?) va in a function to the pathnode it was found in
        if funcStart != self.lastFunc:
            emu = self.vw.getEmulator(True, True)
            self.logger.debug('Generating va_write_map for function 0x%08x', funcStart)
            self.regMon = RegMonitor(regs)
            emu.setEmulationMonitor(self.regMon)
            emu.runFunction(funcStart, maxhit=1, maxloop=1)
            #cache the last va_write_map for a given function
            self.va_write_map = {}
            self.va_read_map = {}
            self.lastFunc = funcStart
            path_bfs(emu.path, build_emu_va_map, res=self.va_write_map, emu=emu, logtype='writelog')
            path_bfs(emu.path, build_emu_va_map, res=self.va_read_map, emu=emu, logtype='readlog')
        else:
            self.logger.debug('Using cached va_write_map')
        #self.logger.debug('Len va_write_map: %d', len(self.va_write_map))
        #for cVa, wlog in self.va_write_map.items():
        #    self.logger.debug('0x%08x: %s', cVa, formatWriteLogEntry(wlog))

        baseEntry = self.va_write_map.get(va, None)
        if baseEntry is None:
            self.logger.error('Node does not have write log. Requires a call instruction (which writes to the stack) for this to work: 0x%08x', va)
            return []
        self.startSp = baseEntry[1]
        return self.analyzeTracker(baseEntry, va, num, regs)

    def analyzeTracker(self, baseEntry, va, num, regs):
        self.logger.debug('analyzeTracker 0x%x, %d', va, num)
        #funcStart = idc.GetFunctionAttr(va, idc.FUNCATTR_START)
        funcStart = self.vw.getFunction(va)
        initState = TrackerState(self, baseEntry, num, regs)
        count = 0
        ret = []
        touched = set()
        self.queue = [ (va, initState) ]
        while len(self.queue) != 0:
            if count > self.maxIters:
                self.logger.error('Max graph traveral iterations reached: (0x%08x) %d. Stopping early. Consider increasing ArgTracker maxIters (unless this is a bug)', va, count)
                break
            cVa, cState = self.queue.pop(0)
            touched.add(cVa)
            #self.logger.debug('Examining 0x%08x: %s', cVa, str(cState))
            #self.logger.debug('Current tempMapping: 0x%08x %s', cVa, pprint.pformat(cState.tempMapping))
            try:
                cState.processWriteLog(self, cVa)
                #self.logger.debug('writelog 0x%08x done', cVa)
                cState.processRegMon(self, cVa)
                #self.logger.debug('regmon 0x%08x done', cVa)
            except Exception, err:
                self.logger.exception('Error in process: %s', str(err))
                return []
            if cState.isComplete():
                self.logger.debug('Yep, appending')
                ret.append(cState.resultArgs)
            else:
                if cVa == funcStart:
                    #self.logger.debug('Skipping xref queueing: hit function start')
                    pass
                else:
                    #self.logger.debug('Not complete: queuing prev items')
                    #for ref in idautils.CodeRefsTo(cVa, True):
                    for ref, _, _, _ in getAllXrefsTo(self.vw, cVa):
                        if ref in touched:
                            #self.logger.debug('Skip queueing (touched) 0x%08x -> 0x%08x', cVa, ref)
                            pass
                        else:
                            #self.logger.debug('Queueing 0x%08x -> 0x%08x', cVa, ref)
                            self.queue.append( (ref, cState.copy()) )
            count += 1
        return ret


def main():
    #jayutils.configLogger(None, logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    logger.debug('Starting up in main')
    #name = idc.AskStr('CreateThread', 'Enter function to find args for')
    name = raw_input('Enter function find args for [CreateThread]: ').strip()
    if name == '':
        name = 'CreateThread'
    #argNum = idc.AskLong(6)
    argNum = raw_input('Enter number of arguments [6]: ').strip()
    if argNum == '':
        argNum = 6
    else:
        argNum = int(argNum)

    #filePath = jayutils.getInputFilepath()
    filePath = sys.argv[1]
    if filePath is None:
        logger.info('No input file provided. Stopping')
        return
    vw = loadWorkspace(filePath)
    logger.debug('Loaded workspace')
    tracker = ArgTracker(vw)

    #import idautils
    #funcEa = idc.LocByName('CreateThread')
    funcEa = BADADDR
    for iva, _, _, impName in vw.getImports():
        if impName.endswith(name):
            funcEa = iva
            break
    #if funcEa == idc.BADADDR:
    if funcEa == BADADDR:
        logger.info('CreateThread not found. Returning now')
        return
    #for xref in idautils.XrefsTo(funcEa):
    for fromva, _, _, _ in getAllXrefsTo(vw, funcEa):
        argsList = tracker.getPushArgs(fromva, 6)
        for argDict in argsList:
            print '-'*60
            pc, value = argDict[3]
            print '0x%08x: 0x%08x: 0x%08x' % (fromva, pc, value)

if __name__ == '__main__':
    main()
