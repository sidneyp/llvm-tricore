//===- TriCoreDisassembler.cpp - Disassembler for TriCore -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// \brief This file is part of the TriCore Disassembler.
///
//===----------------------------------------------------------------------===//

#include "TriCore.h"
#include "TriCoreRegisterInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCFixedLenDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

#define DEBUG_TYPE "tricore-disassembler"

typedef MCDisassembler::DecodeStatus DecodeStatus;

namespace {

/// \brief A disassembler class for TriCore.
class TriCoreDisassembler : public MCDisassembler {
public:
  TriCoreDisassembler(const MCSubtargetInfo &STI, MCContext &Ctx) :
    MCDisassembler(STI, Ctx) {}

  DecodeStatus getInstruction(MCInst &Instr, uint64_t &Size,
                              ArrayRef<uint8_t> Bytes, uint64_t Address,
                              raw_ostream &VStream,
                              raw_ostream &CStream) const override;
};
}

static bool readInstruction16(ArrayRef<uint8_t> Bytes, uint64_t Address,
                              uint64_t &Size, uint16_t &Insn) {
  // We want to read exactly 2 Bytes of data.
  if (Bytes.size() < 2) {
    Size = 0;
    return false;
  }
  // Encoded as a little-endian 16-bit word in the stream.
  Insn = (Bytes[0] << 0) | (Bytes[1] << 8);
  return true;
}

static bool readInstruction32(ArrayRef<uint8_t> Bytes, uint64_t Address,
                              uint64_t &Size, uint32_t &Insn) {
  // We want to read exactly 4 Bytes of data.
  if (Bytes.size() < 4) {
    Size = 0;
    return false;
  }
  // Encoded as a little-endian 32-bit word in the stream.
  Insn =
      (Bytes[0] << 0) | (Bytes[1] << 8) | (Bytes[2] << 16) | (Bytes[3] << 24);
  return true;
}

static unsigned getReg(const void *D, unsigned RC, unsigned RegNo) {
  const TriCoreDisassembler *Dis = static_cast<const TriCoreDisassembler*>(D);
  const MCRegisterInfo *RegInfo = Dis->getContext().getRegisterInfo();
  return *(RegInfo->getRegClass(RC).begin() + RegNo);
}

static DecodeStatus DecodeDataRegsRegisterClass(MCInst &Inst,
                                              unsigned RegNo,
                                              uint64_t Address,
                                              const void *Decoder);

static DecodeStatus DecodeAddrRegsRegisterClass(MCInst &Inst,
                                             unsigned RegNo,
                                             uint64_t Address,
                                             const void *Decoder);

static DecodeStatus DecodeExtRegsRegisterClass(MCInst &Inst,
                                             unsigned RegNo,
                                             uint64_t Address,
                                             const void *Decoder);

static DecodeStatus DecodePSRegsRegisterClass(MCInst &Inst,
                                             unsigned RegNo,
                                             uint64_t Address,
                                             const void *Decoder);

#include "TriCoreGenDisassemblerTables.inc"

static DecodeStatus DecodeDataRegsRegisterClass(MCInst &Inst,
                                              unsigned RegNo,
                                              uint64_t Address,
                                              const void *Decoder)
{
  if (RegNo > 15)
    return MCDisassembler::Fail;
  unsigned Reg = getReg(Decoder, TriCore::DataRegsRegClassID, RegNo);
  Inst.addOperand(MCOperand::createReg(Reg));
  return MCDisassembler::Success;
}

static DecodeStatus DecodeAddrRegsRegisterClass(MCInst &Inst,
                                             unsigned RegNo,
                                             uint64_t Address,
                                             const void *Decoder)
{
  if (RegNo < 16 || RegNo > 31)
    return MCDisassembler::Fail;
  unsigned Reg = getReg(Decoder, TriCore::AddrRegsRegClassID, RegNo);
  Inst.addOperand(MCOperand::createReg(Reg));
  return MCDisassembler::Success;
}

static DecodeStatus DecodeExtRegsRegisterClass(MCInst &Inst,
                                             unsigned RegNo,
                                             uint64_t Address,
                                             const void *Decoder)
{
  if (RegNo < 32 || RegNo > 39)
    return MCDisassembler::Fail;
  unsigned Reg = getReg(Decoder, TriCore::ExtRegsRegClassID, RegNo);
  Inst.addOperand(MCOperand::createReg(Reg));
  return MCDisassembler::Success;
}

static DecodeStatus DecodePSRegsRegisterClass(MCInst &Inst,
                                             unsigned RegNo,
                                             uint64_t Address,
                                             const void *Decoder)
{
  if (RegNo < 40 || RegNo > 43)
    return MCDisassembler::Fail;
  unsigned Reg = getReg(Decoder, TriCore::PSRegsRegClassID, RegNo);
  Inst.addOperand(MCOperand::createReg(Reg));
  return MCDisassembler::Success;
}

MCDisassembler::DecodeStatus TriCoreDisassembler::getInstruction(
    MCInst &instr, uint64_t &Size, ArrayRef<uint8_t> Bytes, uint64_t Address,
    raw_ostream &vStream, raw_ostream &cStream) const {
  uint16_t insn16;

  if (!readInstruction16(Bytes, Address, Size, insn16)) {
    return Fail;
  }

  // Calling the auto-generated decoder function.
  DecodeStatus Result = decodeInstruction(DecoderTable16, instr, insn16,
                                          Address, this, STI);
  if (Result != Fail) {
    Size = 2;
    return Result;
  }

  uint32_t insn32;

  if (!readInstruction32(Bytes, Address, Size, insn32)) {
    return Fail;
  }

  // Calling the auto-generated decoder function.
  Result = decodeInstruction(DecoderTable32, instr, insn32, Address, this, STI);
  if (Result != Fail) {
    Size = 4;
    return Result;
  }

  return Fail;
}

namespace llvm {
  extern Target TheTriCoreTarget;
}

static MCDisassembler *createTriCoreDisassembler(const Target &T,
                                               const MCSubtargetInfo &STI,
                                               MCContext &Ctx) {
  return new TriCoreDisassembler(STI, Ctx);
}

extern "C" void LLVMInitializeTriCoreDisassembler() {
  // Register the disassembler.
  TargetRegistry::RegisterMCDisassembler(TheTriCoreTarget,
                                         createTriCoreDisassembler);
}
