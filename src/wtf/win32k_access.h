// win32k_access.hpp - the target-access primitives, as plain callables.
//
// Deliberately not tied to any particular harness. Capture and write need four
// operations; how you spell them is your business:
//
//   ReadReg (Reg)                    -> uint64     required by capture
//   ReadMem (gva, dst, n)            -> bool       required by capture
//   WriteMem(gva, src, n)            -> bool       required by write
//   SetReg  (Reg, uint64)            -> void       required by write
//
// The register enum is ours so nothing here depends on a foreign one. Map it to
// whatever your primitives take - an enum, a string, an index - in the lambda.
//
// Binding examples
// ----------------
// free functions taking your own enum:
//
//   Access a;
//   a.read_reg  = [](Reg r) { return GetReg(ToMyReg(r)); };
//   a.read_mem  = [](uint64_t g, void* d, size_t n) { return VirtRead(g, d, n); };
//
// member functions on a debugger/emulator object:
//
//   a.read_reg  = [&](Reg r) { return dbg.GetReg(name(r)); };
//   a.read_mem  = [&](uint64_t g, void* d, size_t n) { return dbg.ReadMemory(g, d, n); };
//
// wtf's Backend_t, if that is what you have:
//
//   a.read_reg  = [&](Reg r) { return b.GetReg(ToWtf(r)); };
//   a.read_mem  = [&](uint64_t g, void* d, size_t n) {
//                     return b.VirtRead(Gva_t(g), (uint8_t*)d, n); };
//   a.write_mem = [&](uint64_t g, const void* s, size_t n) {
//                     return b.VirtWriteDirty(Gva_t(g), (const uint8_t*)s, n); };
//   a.set_reg   = [&](Reg r, uint64_t v) { b.SetReg(ToWtf(r), v); };
//
// A snapshot harness must use its DIRTY write, whatever it is called. Without dirty
// tracking the page is not restored between testcases and a mutation leaks into every
// run that follows - which presents as a non-reproducible kernel bug.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace win32k::access {

/// The registers this code touches. Nothing else is needed.
enum class Reg { Rax, Rcx, Rdx, Rsp, R8, R9, R10 };

inline const char* regName(Reg r) {
    switch (r) {
        case Reg::Rax: return "rax";
        case Reg::Rcx: return "rcx";
        case Reg::Rdx: return "rdx";
        case Reg::Rsp: return "rsp";
        case Reg::R8:  return "r8";
        case Reg::R9:  return "r9";
        case Reg::R10: return "r10";
    }
    return "?";
}

using ReadReg  = std::function<std::uint64_t(Reg)>;
using ReadMem  = std::function<bool(std::uint64_t gva, void* dst, std::size_t n)>;
using WriteMem = std::function<bool(std::uint64_t gva, const void* src, std::size_t n)>;
using SetReg   = std::function<void(Reg, std::uint64_t)>;

/// Whatever subset you provide. Capture uses the two readers; writing also needs the
/// two writers. A missing one is checked rather than called.
struct Access {
    ReadReg  read_reg;
    ReadMem  read_mem;
    WriteMem write_mem;
    SetReg   set_reg;

    bool canRead()  const { return read_reg && read_mem; }
    bool canWrite() const { return canRead() && write_mem && set_reg; }
};

/// Where the target is parked, which decides where argument 0 lives.
///
/// SYSCALL overwrites RCX with the return RIP, so a win32u stub begins `mov r10, rcx`:
/// at the instruction argument 0 is in R10, at the export it is in RCX. Reading the
/// wrong one captures an unrelated register, or discovers the wrong buffer address and
/// rewrites whatever lives there.
enum class Entry { SyscallInstruction, Win32uStub };

inline Reg argReg(std::size_t i, Entry e) {
    static const Reg sys[]  = {Reg::R10, Reg::Rdx, Reg::R8, Reg::R9};
    static const Reg stub[] = {Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9};
    return (e == Entry::Win32uStub ? stub : sys)[i];
}

/// Address of a STACK argument: RSP + 8 + i*8, so argument 4 sits at RSP+0x28.
/// Arguments 0..3 are in registers and have no address.
inline std::uint64_t argAddress(std::uint64_t rsp, std::size_t i) { return rsp + 8 + i * 8; }

}  // namespace win32k::access
