package proc

import (
	"encoding/binary"

	"golang.org/x/arch/arm64/arm64asm"
)

var maxInstructionLength uint64 = 15

type ArchInst arm64asm.Inst

func asmDecode(mem []byte, pc uint64) (*ArchInst, error) {
	inst, err :=arm64asm.Decode(mem, 64)
	if err != nil {
		return nil, err
	}
	patchPCRel(pc, &inst)
	r := ArchInst(inst)
	return &r, nil
}

func (inst *ArchInst) Size() int {
	return inst.Len
}

// converts PC relative arguments to absolute addresses
func patchPCRel(pc uint64, inst *arm64asm.Inst) {
	for i := range inst.Args {
		rel, isrel := inst.Args[i].(arm64asm.Rel)
		if isrel {
			inst.Args[i] = arm64asm.Imm(int64(pc) + int64(rel) + int64(inst.Len))
		}
	}
}

func (inst *AsmInstruction) Text(flavour AssemblyFlavour, bi *BinaryInfo) string {
	if inst.Inst == nil {
		return "?"
	}

	var text string

	switch flavour {
	case GNUFlavour:
		text = arm64asm.GNUSyntax(arm64asm.Inst(*inst.Inst), inst.Loc.PC, bi.symLookup)
	case GoFlavour:
		text = arm64asm.GoSyntax(arm64asm.Inst(*inst.Inst), inst.Loc.PC, bi.symLookup)
	case IntelFlavour:
		fallthrough
	default:
		text = arm64asm.IntelSyntax(arm64asm.Inst(*inst.Inst), inst.Loc.PC, bi.symLookup)
	}

	return text
}

func (inst *AsmInstruction) IsCall() bool {
	return inst.Inst.Op == arm64asm.CALL || inst.Inst.Op == arm64asm.LCALL
}

func resolveCallArg(inst *ArchInst, currentGoroutine bool, regs Registers, mem MemoryReadWriter, bininfo *BinaryInfo) *Location {
	if inst.Op != arm64asm.CALL && inst.Op != arm64asm.LCALL {
		return nil
	}

	var pc uint64
	var err error

	switch arg := inst.Args[0].(type) {
	case arm64asm.Imm:
		pc = uint64(arg)
	case arm64asm.Reg:
		if !currentGoroutine || regs == nil {
			return nil
		}
		pc, err = regs.Get(int(arg))
		if err != nil {
			return nil
		}
	case arm64asm.Mem:
		if !currentGoroutine || regs == nil {
			return nil
		}
		if arg.Segment != 0 {
			return nil
		}
		base, err1 := regs.Get(int(arg.Base))
		index, err2 := regs.Get(int(arg.Index))
		if err1 != nil || err2 != nil {
			return nil
		}
		addr := uintptr(int64(base) + int64(index*uint64(arg.Scale)) + arg.Disp)
		//TODO: should this always be 64 bits instead of inst.MemBytes?
		pcbytes := make([]byte, inst.MemBytes)
		_, err := mem.ReadMemory(pcbytes, addr)
		if err != nil {
			return nil
		}
		pc = binary.LittleEndian.Uint64(pcbytes)
	default:
		return nil
	}

	file, line, fn := bininfo.PCToLine(pc)
	if fn == nil {
		return nil
	}
	return &Location{PC: pc, File: file, Line: line, Fn: fn}
}

type instrseq []arm64asm.Op

// Possible stacksplit prologues are inserted by stacksplit in
// $GOROOT/src/cmd/internal/obj/arm64/obj7.go. //TODO determine if relevant
// The stacksplit prologue will always begin with loading curg in CX, this
// instruction is added by load_g_cx in the same file and is either 1 or 2
// MOVs.
var prologues []instrseq

func init() {
	var tinyStacksplit = instrseq{arm64asm.CMP, arm64asm.JBE}
	var smallStacksplit = instrseq{arm64asm.LEA, arm64asm.CMP, arm64asm.JBE}
	var bigStacksplit = instrseq{arm64asm.MOV, arm64asm.CMP, arm64asm.JE, arm64asm.LEA, arm64asm.SUB, arm64asm.CMP, arm64asm.JBE}
	var unixGetG = instrseq{arm64asm.MOV}
	var windowsGetG = instrseq{arm64asm.MOV, arm64asm.MOV}

	prologues = make([]instrseq, 0, 2*3)
	for _, getG := range []instrseq{unixGetG, windowsGetG} {
		for _, stacksplit := range []instrseq{tinyStacksplit, smallStacksplit, bigStacksplit} {
			prologue := make(instrseq, 0, len(getG)+len(stacksplit))
			prologue = append(prologue, getG...)
			prologue = append(prologue, stacksplit...)
			prologues = append(prologues, prologue)
		}
	}
}

// firstPCAfterPrologueDisassembly returns the address of the first
// instruction after the prologue for function fn by disassembling fn and
// matching the instructions against known split-stack prologue patterns.
// If sameline is set firstPCAfterPrologueDisassembly will always return an
// address associated with the same line as fn.Entry
func firstPCAfterPrologueDisassembly(p Process, fn *Function, sameline bool) (uint64, error) {
	var mem MemoryReadWriter = p.CurrentThread()
	breakpoints := p.Breakpoints()
	bi := p.BinInfo()
	text, err := disassemble(mem, nil, breakpoints, bi, fn.Entry, fn.End, false)
	if err != nil {
		return fn.Entry, err
	}

	if len(text) <= 0 {
		return fn.Entry, nil
	}

	for _, prologue := range prologues {
		if len(prologue) >= len(text) {
			continue
		}
		if checkPrologue(text, prologue) {
			r := &text[len(prologue)]
			if sameline {
				if r.Loc.Line != text[0].Loc.Line {
					return fn.Entry, nil
				}
			}
			return r.Loc.PC, nil
		}
	}

	return fn.Entry, nil
}

func checkPrologue(s []AsmInstruction, prologuePattern instrseq) bool {
	line := s[0].Loc.Line
	for i, op := range prologuePattern {
		if s[i].Inst.Op != op || s[i].Loc.Line != line {
			return false
		}
	}
	return true
}
