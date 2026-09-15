// win32k_write.hpp - rewrite a CallFrame's data into memory the snapshot ALREADY owns,
// through wtf's Backend_t.
//
//   https://github.com/0vercl0k/wtf/blob/main/src/wtf/backend.h
//
// The snapshot model: execution is parked at the syscall, every pointer argument
// already points at mapped user memory, and every pointer FIELD inside those buffers
// already holds a valid address. Nothing is allocated; each iteration rewrites contents.
//
// ---------------------------------------------------------------------------
// Three things that bite when the memory already exists
//
//   1. Addresses are DISCOVERED, not assigned - read back from the register or stack
//      slot the snapshot left them in.
//   2. Relocations are PRESERVED, not applied. A region's byte image holds zero at each
//      pointer field; writing it wholesale would overwrite a valid snapshot pointer.
//      Writes go around those offsets.
//   3. Sizes are CAPPED. A mutation can grow an array past the buffer the snapshot has.
//
// None of these fail loudly. They damage the snapshot quietly and every later iteration
// inherits the damage.
//
// ---------------------------------------------------------------------------
// Two Backend_t details that matter here
//
//   * VirtWriteDirty, not VirtWrite. Without dirty tracking the page is not restored
//     between testcases, so a mutation leaks into every run that follows - which looks
//     exactly like a non-reproducible kernel bug.
//   * GetArg8(0) returns RCX. That is the Windows x64 CALL convention, and it is wrong
//     at a syscall-instruction entry where argument 0 lives in R10. This code picks the
//     register from Entry rather than going through GetArg8.
//
// Build with WIN32K_WTF_STANDALONE to use the stub backend in include/wtfstub.
#pragma once

#include "backend.h"
#include "win32k_argvalue.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <unordered_map>
#include <vector>

namespace win32k::target {

using namespace win32k::value;

/// Where execution is parked, which decides where argument 0 lives.
///
/// SYSCALL overwrites RCX with the return RIP, so every win32u stub begins
/// `mov r10, rcx`. Parked at the instruction, argument 0 is in R10; parked at the
/// export, in RCX. Reading the wrong one discovers the wrong buffer address and then
/// rewrites whatever happens to live there.
enum class Entry { SyscallInstruction, Win32uStub };

/// What to do with a buffer reached through a pointer field inside another buffer.
enum class NestedPolicy { Follow, Skip };

struct WriteOptions {
    Entry        entry   = Entry::SyscallInstruction;
    NestedPolicy nested  = NestedPolicy::Follow;
    bool         set_ssn = true;      ///< load RAX with the syscall number
    /// Upper bound on bytes written into any one buffer. The snapshot's real capacity
    /// is not discoverable from here, so this is the valve against a grown array.
    std::size_t  max_bytes_per_region = 0x1000;
    /// Per-argument capacities where the harness does know them; overrides the cap.
    std::unordered_map<std::size_t, std::size_t> capacity;
    std::size_t  max_nested_depth = 4;
};

struct PlacedCall {
    std::uint32_t              ssn = 0;
    std::uint64_t              rsp = 0;
    std::uint64_t              regs[4]{};
    std::vector<std::uint64_t> stack;
    std::size_t bytes_written = 0, buffers_rewritten = 0;
    std::size_t truncated = 0, nested_unreachable = 0;
    bool        ok = true;
};

class InPlaceWriter {
public:
    explicit InPlaceWriter(Backend_t &backend, WriteOptions opt = {})
        : b_(backend), opt_(std::move(opt)) {}

    const WriteOptions& options() const { return opt_; }
    WriteOptions&       options()       { return opt_; }

    /// The register argument `i` lives in, for this entry point.
    Registers_t ArgReg(std::size_t i) const {
        static const Registers_t sys[]  = {Registers_t::R10, Registers_t::Rdx,
                                           Registers_t::R8,  Registers_t::R9};
        static const Registers_t stub[] = {Registers_t::Rcx, Registers_t::Rdx,
                                           Registers_t::R8,  Registers_t::R9};
        return (opt_.entry == Entry::Win32uStub ? stub : sys)[i];
    }

    /// Address of a STACK argument. Matches Backend_t::GetArgAddress, which aborts for
    /// Idx <= 3 - those are in registers and have no address.
    Gva_t ArgAddress(std::size_t i) const {
        return Gva_t(b_.GetReg(Registers_t::Rsp) + 8 + i * 8);
    }

    /// Rewrite one argument's data at an address the snapshot already owns.
    std::size_t WriteArgumentAt(BoundArg& a, Gva_t gva, PlacedCall& out,
                                std::size_t depth = 0) {
        Region* r = a.region();
        if (!r || r->empty() || !gva.U64()) return 0;
        return WriteRegion(a.frame(), a.value().region, gva, Capacity(a.index()),
                           out, depth);
    }

    /// Rewrite a whole frame in place.
    ///
    /// A Pointer argument keeps the snapshot's address and only its contents change.
    /// The exception is an argument a mutation turned into a RawPointer: that IS the
    /// mutation, so the slot is set to the wild address and nothing is written through it.
    PlacedCall WriteFrame(FrameView& view) {
        PlacedCall out;
        out.ssn = view.frame().ssn();
        out.rsp = b_.GetReg(Registers_t::Rsp);
        seen_.clear();

        for (std::size_t i = 0; i < view.size(); ++i) {
            BoundArg a = view[i];
            const ArgValue& v = a.value();
            const std::uint64_t existing = ReadSlot(i);

            switch (v.kind) {
                case ValueKind::Pointer: {
                    if (WriteArgumentAt(a, Gva_t(existing), out)) ++out.buffers_rewritten;
                    StoreSlot(i, existing, out);          // unchanged, but recorded
                    break;
                }
                case ValueKind::RawPointer: StoreSlot(i, v.raw, out); break;
                case ValueKind::Scalar:
                    StoreSlot(i, v.width == 4 ? (v.raw & 0xFFFF'FFFFull) : v.raw, out);
                    break;
                case ValueKind::Handle:     StoreSlot(i, v.raw, out); break;
                case ValueKind::Null:       StoreSlot(i, 0, out);     break;
            }
        }

        // SetReg returns the register value, not a success flag, so there is nothing
        // to check here.
        if (opt_.set_ssn) b_.SetReg(Registers_t::Rax, out.ssn);
        out.ok = out.ok && !failed_;
        return out;
    }

    void Reset()        { failed_ = false; seen_.clear(); }
    bool Failed() const { return failed_; }

private:
    std::size_t Capacity(std::size_t i) const {
        auto it = opt_.capacity.find(i);
        return it != opt_.capacity.end() ? it->second : opt_.max_bytes_per_region;
    }

    std::uint64_t ReadSlot(std::size_t i) {
        if (i < 4) return b_.GetReg(ArgReg(i));
        std::uint64_t v = 0;
        if (!b_.VirtRead(ArgAddress(i), reinterpret_cast<std::uint8_t*>(&v), sizeof(v)))
            failed_ = true;
        return v;
    }

    void StoreSlot(std::size_t i, std::uint64_t value, PlacedCall& out) {
        if (i < 4) {
            out.regs[i] = value;
            b_.SetReg(ArgReg(i), value);
        } else {
            if (!b_.VirtWriteDirty(ArgAddress(i),
                                   reinterpret_cast<const std::uint8_t*>(&value),
                                   sizeof(value)))
                out.ok = false;
            out.stack.push_back(value);
            out.bytes_written += sizeof(value);
        }
    }

    /// Write a region's bytes at `gva`, skipping the offsets that hold pointers.
    std::size_t WriteRegion(CallFrame& f, RegionId id, Gva_t gva, std::size_t cap,
                            PlacedCall& out, std::size_t depth) {
        if (id == kNoRegion || !gva.U64()) return 0;
        // A region can be reached twice and can point at itself; writing it once is
        // enough and terminates the recursion.
        if (!seen_.insert({id, gva.U64()}).second) return 0;
        if (depth > opt_.max_nested_depth) return 0;

        Region& r = f.region(id);
        std::size_t n = r.size();
        if (n > cap) { n = cap; ++out.truncated; }
        if (!n) return 0;

        std::vector<std::pair<std::size_t, std::size_t>> holes;
        for (const Reloc& rl : r.relocs)
            if (rl.offset < n)
                holes.emplace_back(rl.offset, std::min<std::size_t>(8, n - rl.offset));
        std::sort(holes.begin(), holes.end());

        std::size_t written = 0, pos = 0;
        const auto put = [&](std::size_t at, std::size_t len) {
            if (!len) return;
            if (!b_.VirtWriteDirty(Gva_t(gva.U64() + at), r.bytes.data() + at, len))
                failed_ = true;
            written += len;
        };
        for (const auto& [off, len] : holes) {
            if (off > pos) put(pos, off - pos);
            pos = std::max(pos, off + len);
        }
        if (pos < n) put(pos, n - pos);
        out.bytes_written += written;

        // Follow each pointer field to the buffer the snapshot already has there.
        if (opt_.nested == NestedPolicy::Follow) {
            for (const Reloc& rl : r.relocs) {
                if (rl.offset + 8 > n || rl.target == kNoRegion) continue;
                std::uint64_t inner = 0;
                if (!b_.VirtRead(Gva_t(gva.U64() + rl.offset),
                                 reinterpret_cast<std::uint8_t*>(&inner), sizeof(inner))
                    || !inner) {
                    ++out.nested_unreachable;
                    continue;
                }
                if (WriteRegion(f, rl.target,
                                Gva_t(inner - static_cast<std::uint64_t>(rl.addend)),
                                opt_.max_bytes_per_region, out, depth + 1))
                    ++out.buffers_rewritten;
            }
        } else {
            for (const Reloc& rl : r.relocs)
                if (rl.offset + 8 <= n && rl.target != kNoRegion) ++out.nested_unreachable;
        }
        return written;
    }

    Backend_t   &b_;
    WriteOptions opt_;
    std::set<std::pair<RegionId, std::uint64_t>> seen_;
    bool failed_ = false;
};

}  // namespace win32k::target
