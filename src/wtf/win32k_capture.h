// win32k_capture.hpp - capture a live syscall's arguments into a CallFrame, and write
// it out as a win32k.callframe JSON document.
//
// The inverse of win32k_write.hpp. Park the target at a syscall, read the registers and
// the buffers they point at, and the result is a corpus seed carrying real handles, real
// structure contents and real lengths - rather than the synthetic frame buildFrame()
// produces from the prototype alone.
//
// Needs only two primitives, supplied as callables through win32k::access::Access:
//
//   read_reg(Reg)              -> uint64
//   read_mem(gva, dst, n)      -> bool
//
// Nothing is written to the target.
//
// ---------------------------------------------------------------------------
// The one thing that makes this non-trivial
//
// The bytes read back contain REAL ADDRESSES at every pointer-field offset. Storing them
// as-is would tie the frame to the snapshot it came from: replay it after ASLR, in
// another process, or against a re-taken snapshot, and those addresses are meaningless.
//
// So capture does the exact inverse of the in-place write. Where the writer goes *around*
// relocation offsets to preserve the snapshot's pointers, the capturer:
//
//   * follows the address it finds there to read the pointee,
//   * records a relocation pointing at the new region,
//   * and ZEROES those eight bytes in the stored image,
//
// so no snapshot address ever reaches the corpus.
#pragma once

#include "win32k_access.h"
#include "win32k_argvalue.h"

#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>


namespace win32k::capture {

using namespace win32k::value;
using win32k::access::Access;
using win32k::access::Entry;
using win32k::access::Reg;

struct CaptureOptions {
    Entry       entry = Entry::SyscallInstruction;
    /// Bytes to read for a pointer whose pointee size was never recovered.
    std::size_t opaque_size = 0x40;
    /// Never read more than this from one buffer, however large a recovered size or a
    /// captured count claims to be.
    std::size_t max_region = 0x10000;
    /// Elements to read when an array's count argument could not be resolved.
    std::size_t default_elements = 8;
    std::size_t max_nested_depth = 4;
    bool        follow_nested = true;
};

struct CaptureResult {
    bool        ok = false;
    std::string error;
    std::size_t regions = 0, bytes_read = 0;
    std::size_t unreadable = 0;   ///< pointers that could not be dereferenced
    std::size_t clipped = 0;      ///< buffers truncated, by the cap or by a short read
};

class FrameCapturer {
public:
    explicit FrameCapturer(Access access, CaptureOptions opt = {})
        : a_(std::move(access)), opt_(std::move(opt)) {}

    const CaptureOptions& options() const { return opt_; }
    CaptureOptions&       options()       { return opt_; }

    /// The syscall number the target is about to execute, read from RAX. Only
    /// meaningful when parked at the SYSCALL instruction itself.
    std::uint32_t CurrentSsn() const {
        return static_cast<std::uint32_t>(a_.read_reg(Reg::Rax));
    }

    /// Capture the arguments of `proto` as they currently stand in the target.
    std::optional<CallFrame> Capture(const Syscall& proto, CaptureResult* res = nullptr) {
        CaptureResult local;
        CaptureResult& r = res ? *res : local;
        r = CaptureResult{};

        if (!a_.canRead()) { r.error = "read_reg and read_mem are both required"; return std::nullopt; }

        CallFrame f(proto.ssn, proto.name);
        f.setArgCount(static_cast<std::size_t>(proto.nargs));

        // Pass 1: read every slot. Array sizing needs the count argument's value, and
        // the count can sit after the buffer in the argument list.
        const std::uint64_t rsp = a_.read_reg(Reg::Rsp);
        std::vector<std::uint64_t> slot(static_cast<std::size_t>(proto.nargs), 0);
        for (std::size_t i = 0; i < slot.size(); ++i) {
            if (!ReadSlot(i, rsp, slot[i])) {
                r.error = "could not read argument " + std::to_string(i);
                return std::nullopt;
            }
        }

        // Pass 2: build values, following pointers into the target.
        for (const Argument& a : proto.args) {
            const auto i = static_cast<std::size_t>(a.index);
            if (i >= slot.size()) continue;
            const std::uint64_t raw = slot[i];

            if (a.kind == Kind::Handle) { f.setArg(i, ArgValue::handle(raw)); continue; }
            if (!a.isPointerLike()) {
                f.setArg(i, ArgValue::scalar(raw, a.size ? a.size : 8));
                continue;
            }
            if (raw == 0) {
                // A genuine NULL: preserve it rather than inventing a buffer, because
                // NULL is frequently the argument that selects a different code path.
                f.setArg(i, ArgValue::null());
                continue;
            }

            const std::size_t want = WantedBytes(a, slot);
            const RegionId id = ReadRegion(f, raw, want, "a" + std::to_string(i), r, 0);
            if (id == kNoRegion) {
                // Mapped nowhere we can read: keep the address as a literal so the frame
                // still describes what the snapshot actually had, instead of silently
                // becoming NULL.
                ++r.unreadable;
                f.setArg(i, ArgValue::rawPointer(raw));
                continue;
            }
            f.setArg(i, (a.kind == Kind::Array)
                ? ArgValue::array(id,
                      a.array && a.array->element_size ? *a.array->element_size : 1,
                      a.array && a.array->count_arg ? *a.array->count_arg : -1)
                : ArgValue::pointer(id, shapeOf(a)));

            if (opt_.follow_nested) FollowNested(f, id, a, r, 1);
        }

        r.regions = f.regionCount();
        r.ok = true;
        return f;
    }

    /// Capture whatever the target is parked on, resolving the prototype by RAX.
    std::optional<CallFrame> CaptureCurrent(const Database& db, CaptureResult* res = nullptr) {
        const Syscall* s = db.bySsn(CurrentSsn());
        if (!s) {
            if (res) { *res = CaptureResult{}; res->error = "unknown syscall number"; }
            return std::nullopt;
        }
        return Capture(*s, res);
    }

    /// Capture and write a win32k.callframe document.
    bool CaptureToFile(const Syscall& proto, const std::string& path,
                       const SerializeOptions& so = {}, CaptureResult* res = nullptr) {
        auto f = Capture(proto, res);
        if (!f) return false;
        std::ofstream out(path);
        if (!out) { if (res) res->error = "cannot write " + path; return false; }
        out << toJson(*f, so).dump(1) << '\n';
        return true;
    }

private:
    bool ReadSlot(std::size_t i, std::uint64_t rsp, std::uint64_t& out) const {
        if (i < 4) { out = a_.read_reg(access::argReg(i, opt_.entry)); return true; }
        return a_.read_mem(access::argAddress(rsp, i), &out, sizeof(out));
    }

    /// How many bytes to read for a pointer argument.
    std::size_t WantedBytes(const Argument& a, const std::vector<std::uint64_t>& slot) const {
        std::size_t n = 0;
        if (a.kind == Kind::Array && a.array) {
            const std::size_t es = a.array->element_size ? *a.array->element_size : 1;
            std::size_t count = opt_.default_elements;
            if (a.array->count_arg) {
                const auto ci = static_cast<std::size_t>(*a.array->count_arg);
                if (ci < slot.size()) count = static_cast<std::size_t>(slot[ci]);
            }
            // A count read out of the target is attacker-influenced in the general case
            // and can be enormous; max_region is what stops it becoming a huge read.
            const std::size_t per = es ? es : 1;
            n = (count && count < opt_.max_region / per) ? count * per : opt_.max_region;
        } else if (a.pointee && a.pointee->size) {
            n = static_cast<std::size_t>(*a.pointee->size);
        }
        if (!n) n = opt_.opaque_size;
        return std::min(n, opt_.max_region);
    }

    /// Read `n` bytes at `gva` into a new region. kNoRegion if nothing could be read.
    RegionId ReadRegion(CallFrame& f, std::uint64_t gva, std::size_t n,
                        const std::string& label, CaptureResult& r, std::size_t depth) {
        if (!gva || !n || depth > opt_.max_nested_depth) return kNoRegion;
        if (n > opt_.max_region) { n = opt_.max_region; ++r.clipped; }

        std::vector<std::uint8_t> buf(n, 0);
        if (!a_.read_mem(gva, buf.data(), n)) {
            // A short read is ordinary: the buffer runs to the end of a page and the
            // next one is not mapped. Halve until something succeeds rather than
            // discarding the argument.
            std::size_t try_n = n / 2;
            bool got = false;
            while (try_n >= 8) {
                buf.assign(try_n, 0);
                if (a_.read_mem(gva, buf.data(), try_n)) { got = true; n = try_n; break; }
                try_n /= 2;
            }
            if (!got) return kNoRegion;
            ++r.clipped;
        }
        r.bytes_read += n;

        const RegionId id = f.addRegion(n, 8, label);
        f.region(id).bytes = std::move(buf);
        return id;
    }

    /// For each pointer field the prototype knows about, follow the address that is
    /// really there, capture the pointee, record a relocation, and zero the address in
    /// the stored image so no snapshot address reaches the corpus.
    void FollowNested(CallFrame& f, RegionId id, const Argument& a, CaptureResult& r,
                      std::size_t depth) {
        if (depth > opt_.max_nested_depth) return;

        std::vector<std::pair<std::size_t, std::size_t>> fields;   // offset, bytes
        if (a.character_data && a.character_data->form == "unicode_string_struct") {
            // Follow MaximumLength rather than the recovered struct size, which would
            // capture 16 bytes of a string that may be far longer.
            const Region& R = f.region(id);
            const std::size_t max_len = R.size() >= 4 ? R.peek<std::uint16_t>(2) : 0;
            fields.emplace_back(8, max_len ? max_len : opt_.opaque_size);
        } else if (a.pointee) {
            for (const NestedPointer& n : a.pointee->nested_pointers)
                fields.emplace_back(static_cast<std::size_t>(n.at_offset),
                                    n.size > 0 ? static_cast<std::size_t>(n.size)
                                               : opt_.opaque_size);
        }

        for (const auto& [off, size] : fields) {
            if (off + 8 > f.region(id).size()) continue;
            const std::uint64_t inner = f.region(id).peek<std::uint64_t>(off);
            if (!inner) continue;

            const RegionId child =
                ReadRegion(f, inner, size, f.region(id).label + "+0x" + Hex(off), r, depth);
            if (child == kNoRegion) { ++r.unreadable; continue; }

            // addRegion may have reallocated the region vector, so re-resolve first.
            Region& R = f.region(id);
            R.poke<std::uint64_t>(off, 0);
            R.pointerAt(off, child);
        }
    }

    static std::string Hex(std::size_t v) {
        std::ostringstream o; o << std::hex << v; return o.str();
    }

    Access         a_;
    CaptureOptions opt_;
};

}  // namespace win32k::capture
