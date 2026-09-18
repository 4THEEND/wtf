// win32k_argvalue.hpp - runtime container for concrete win32k syscall argument VALUES.
//
// `win32k_syscalls.hpp` describes what an argument *is* (the recovered prototype).
// This header holds what you are about to pass, and knows how to lay it out for the
// x64 syscall ABI, mutate it, and store it in JSON.
//
// ---------------------------------------------------------------------------
// Model
//
//   Region     one owned block of pointee memory. Owns its bytes; pointer fields
//              inside it are recorded as relocations, never as baked-in addresses.
//   ArgValue   one argument. `kind` says how to produce the 64-bit word (scalar,
//              handle, pointer-to-region, literal address); `shape` says how to
//              mutate what it points at (struct, array, string, opaque).
//   CallFrame  owns every Region and ArgValue for one call. marshal() assigns
//              addresses, applies relocations, and produces the register/stack image.
//   BoundArg   an ArgValue paired with its recovered metadata, exposing the
//              mutations that make sense for its shape.
//   FrameView  a CallFrame paired with the prototype it was built from.
//
// Two discriminators, deliberately separate:
//
//   ValueKind  marshalling concern - how to compute the word that goes in the register.
//   Shape      mutation concern    - a struct pointer and an array pointer are both
//              ValueKind::Pointer and are told apart only by Shape.
//
// Addresses are never serialised and never written into a pointer field directly.
// That is what lets a saved frame stay valid under a different allocator, a different
// process, or ASLR.
//
// Nothing here issues a syscall. marshal() produces the ABI image and stops.
//
// Requires C++17 and nlohmann/json >= 3.11.
#pragma once

#include "win32k_syscalls.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace win32k::value {

// ============================================================== identifiers ==

using RegionId = int;
inline constexpr RegionId kNoRegion = -1;

/// Version of the on-disk callframe/corpus format.
inline constexpr int kFrameFormatVersion = 1;

// =================================================================== shape ==

/// How to mutate an argument. Distinct from ValueKind, which is about marshalling.
enum class Shape {
    Unknown,   ///< nothing known - treat conservatively
    Scalar,    ///< integer, enum, flags, BOOL
    Handle,    ///< HWND/HDC/... - usually excluded from mutation
    Struct,    ///< pointer to a layout that was recovered (walk fields())
    Array,     ///< pointer to N elements, count usually in a sibling argument
    String,    ///< UNICODE_STRING, counted WCHAR/CHAR array, or NUL-terminated buffer
    Opaque     ///< pointer whose layout was not recovered - only a size is known
};

inline const char* shapeName(Shape s) {
    switch (s) {
        case Shape::Scalar: return "scalar";
        case Shape::Handle: return "handle";
        case Shape::Struct: return "struct";
        case Shape::Array:  return "array";
        case Shape::String: return "string";
        case Shape::Opaque: return "opaque";
        case Shape::Unknown:
        default:            return "unknown";
    }
}

inline Shape shapeFromName(const std::string& s) {
    if (s == "scalar") return Shape::Scalar;
    if (s == "handle") return Shape::Handle;
    if (s == "struct") return Shape::Struct;
    if (s == "array")  return Shape::Array;
    if (s == "string") return Shape::String;
    if (s == "opaque") return Shape::Opaque;
    return Shape::Unknown;
}

/// Derive the mutation shape from a recovered prototype argument.
inline Shape shapeOf(const Argument& a) {
    switch (a.kind) {
        case Kind::Array:   return Shape::Array;
        case Kind::Handle:  return Shape::Handle;
        case Kind::Scalar:  return Shape::Scalar;
        case Kind::String:  return Shape::String;
        case Kind::Pointer:
        case Kind::Buffer:
            if (a.character_data) return Shape::String;
            return (a.pointee && !a.pointee->fields.empty()) ? Shape::Struct : Shape::Opaque;
        case Kind::Unknown:
        default:            return Shape::Unknown;
    }
}

// ================================================================== region ==

/// A pointer field inside a Region: at `offset`, write address_of(target) + addend.
/// Recorded rather than written, because the target has no address until marshal time.
struct Reloc {
    std::size_t  offset = 0;
    RegionId     target = kNoRegion;
    std::int64_t addend = 0;
};

/// One owned block of memory that a pointer argument points at.
class Region {
public:
    std::vector<std::uint8_t> bytes;
    std::vector<Reloc>        relocs;
    std::size_t               alignment = 8;
    std::string               label;
    std::uint64_t             address = 0;  ///< assigned by marshal(); never serialised

    Region() = default;
    Region(std::size_t size, std::size_t align, std::string lbl)
        : bytes(size, 0), alignment(align ? align : 1), label(std::move(lbl)) {}

    std::size_t size()  const { return bytes.size(); }
    bool        empty() const { return bytes.empty(); }
    bool        isZero() const {
        return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
    }

    void resize(std::size_t n) { bytes.resize(n, 0); }
    void fill(std::uint8_t b)  { std::fill(bytes.begin(), bytes.end(), b); }

    template <typename T>
    void poke(std::size_t off, T v) {
        static_assert(std::is_trivially_copyable_v<T>, "poke needs a trivially copyable type");
        checkRange(off, sizeof(T), "poke");
        std::memcpy(bytes.data() + off, &v, sizeof(T));
    }

    template <typename T>
    T peek(std::size_t off) const {
        static_assert(std::is_trivially_copyable_v<T>, "peek needs a trivially copyable type");
        checkRange(off, sizeof(T), "peek");
        T v{};
        std::memcpy(&v, bytes.data() + off, sizeof(T));
        return v;
    }

    void pokeBytes(std::size_t off, const void* src, std::size_t n) {
        checkRange(off, n, "pokeBytes");
        std::memcpy(bytes.data() + off, src, n);
    }

    /// Typed view, for filling an array element-wise.
    template <typename T> T*          as()       { return reinterpret_cast<T*>(bytes.data()); }
    template <typename T> const T*    as() const { return reinterpret_cast<const T*>(bytes.data()); }
    template <typename T> std::size_t countOf() const { return bytes.size() / sizeof(T); }

    /// Declare that the 8 bytes at `off` point at `target` (+ addend).
    void pointerAt(std::size_t off, RegionId target, std::int64_t addend = 0) {
        checkRange(off, 8, "pointerAt");
        clearPointerAt(off);
        relocs.push_back(Reloc{off, target, addend});
    }

    /// Drop the relocation at `off` so a mutator can write a literal address there.
    void clearPointerAt(std::size_t off) {
        relocs.erase(std::remove_if(relocs.begin(), relocs.end(),
                                    [&](const Reloc& r) { return r.offset == off; }),
                     relocs.end());
    }

private:
    void checkRange(std::size_t off, std::size_t n, const char* what) const {
        if (off + n > bytes.size() || off + n < off) {
            std::ostringstream o;
            o << what << " at +0x" << std::hex << off << " (" << std::dec << n
              << " bytes) is past the end of region '" << label << "' ("
              << bytes.size() << " bytes)";
            throw std::out_of_range(o.str());
        }
    }
};

// =============================================================== arg value ==

enum class ValueKind {
    Null,       ///< a literal 0 - covers a NULL pointer and a zero scalar alike
    Scalar,     ///< integer / enum / BOOL / flags
    Handle,     ///< kept distinct so a mutator can leave handles alone
    Pointer,    ///< points at a Region owned by the CallFrame
    RawPointer  ///< a literal address, for deliberately invalid or kernel-range pointers
};

inline const char* valueKindName(ValueKind k) {
    switch (k) {
        case ValueKind::Scalar:     return "scalar";
        case ValueKind::Handle:     return "handle";
        case ValueKind::Pointer:    return "pointer";
        case ValueKind::RawPointer: return "raw_pointer";
        case ValueKind::Null:
        default:                    return "null";
    }
}

inline ValueKind valueKindFromName(const std::string& s) {
    if (s == "scalar")      return ValueKind::Scalar;
    if (s == "handle")      return ValueKind::Handle;
    if (s == "pointer")     return ValueKind::Pointer;
    if (s == "raw_pointer") return ValueKind::RawPointer;
    if (s == "null")        return ValueKind::Null;
    throw std::runtime_error("unknown ArgValue kind '" + s + "'");
}

/// The concrete value of one argument. Small and copyable; any memory it points at
/// lives in the CallFrame, so cloning and mutating an ArgValue is cheap.
class ArgValue {
public:
    ValueKind     kind   = ValueKind::Null;
    std::uint64_t raw    = 0;          ///< Scalar / Handle / RawPointer payload
    RegionId      region = kNoRegion;  ///< Pointer target
    std::int64_t  offset = 0;          ///< byte offset into that region
    int           width  = 8;          ///< 4 or 8; a 4-byte argument still fills an 8-byte slot

    // Self-describing hints. Filled by buildFrame() and preserved through JSON, so a
    // corpus entry stays correctly mutable without shipping the type database with it.
    Shape shape     = Shape::Unknown;
    int   elem_size = 0;   ///< Shape::Array: bytes per element
    int   count_arg = -1;  ///< Shape::Array: index of the argument holding the count

    static ArgValue null() { return ArgValue{}; }

    static ArgValue scalar(std::uint64_t v, int w = 8) {
        ArgValue a; a.kind = ValueKind::Scalar; a.raw = v; a.width = w;
        a.shape = Shape::Scalar; return a;
    }
    static ArgValue handle(std::uint64_t v) {
        ArgValue a; a.kind = ValueKind::Handle; a.raw = v; a.shape = Shape::Handle; return a;
    }
    static ArgValue pointer(RegionId r, Shape s = Shape::Opaque, std::int64_t off = 0) {
        ArgValue a; a.kind = ValueKind::Pointer; a.region = r; a.offset = off; a.shape = s;
        return a;
    }
    static ArgValue array(RegionId r, int elemSize, int countArg = -1) {
        ArgValue a = pointer(r, Shape::Array);
        a.elem_size = elemSize;
        a.count_arg = countArg;
        return a;
    }
    static ArgValue rawPointer(std::uint64_t addr) {
        ArgValue a; a.kind = ValueKind::RawPointer; a.raw = addr; return a;
    }

    bool isPointer() const { return kind == ValueKind::Pointer || kind == ValueKind::RawPointer; }
    bool isArray()   const { return shape == Shape::Array;  }
    bool isStruct()  const { return shape == Shape::Struct; }
    bool isString()  const { return shape == Shape::String; }
};

// ============================================================== marshalling ==

/// The register/stack image for one call. Argument 0 lands in R10 at the SYSCALL
/// instruction - RCX when calling the win32u export, because SYSCALL overwrites RCX
/// with the return RIP. Arguments 4+ sit at [RSP + 0x28 + 8*(i-4)].
struct MarshalledCall {
    static constexpr std::size_t kFirstStackOffset = 0x28;

    /// One region as it would appear in memory: address assigned, relocations applied.
    struct Image {
        RegionId                  id      = kNoRegion;
        std::uint64_t             address = 0;
        std::vector<std::uint8_t> bytes;
    };

    std::uint32_t              ssn = 0;
    std::uint64_t              r10 = 0, rdx = 0, r8 = 0, r9 = 0;
    std::vector<std::uint64_t> stack;  ///< stack[k] is argument 4+k
    std::vector<Image>         memory; ///< the relocated bytes, NOT written back

    std::uint64_t reg(int i) const {
        switch (i) {
            case 0:  return r10;
            case 1:  return rdx;
            case 2:  return r8;
            case 3:  return r9;
            default: throw std::out_of_range("register index must be 0..3");
        }
    }
    /// The 64-bit word for argument `i`, wherever it lives.
    std::uint64_t argument(std::size_t i) const {
        return i < 4 ? reg(static_cast<int>(i)) : stack.at(i - 4);
    }
    static std::size_t stackOffset(std::size_t argIndex) {
        if (argIndex < 4) throw std::invalid_argument("arguments 0..3 live in registers");
        return kFirstStackOffset + 8 * (argIndex - 4);
    }
};

/// Hands out addresses for regions. On Windows this wraps VirtualAlloc; the default
/// simulates allocation so a harness can be exercised without touching the kernel.
using Allocator = std::function<std::uint64_t(std::size_t size, std::size_t align)>;

inline Allocator simulatedAllocator(std::uint64_t base = 0x0000'0200'0000'0000ull) {
    auto cursor = std::make_shared<std::uint64_t>(base);
    return [cursor](std::size_t size, std::size_t align) {
        const std::uint64_t a = align ? align : 8;
        *cursor = (*cursor + a - 1) & ~(a - 1);
        const std::uint64_t here = *cursor;
        *cursor += (size + 0xFFF) & ~static_cast<std::uint64_t>(0xFFF);  // page granular
        return here;
    };
}

// =============================================================== callframe ==

/// Owns every Region and ArgValue for one syscall invocation.
class CallFrame {
public:
    CallFrame() = default;
    explicit CallFrame(std::uint32_t ssn, std::string name = {})
        : ssn_(ssn), name_(std::move(name)) {}

    std::uint32_t      ssn()  const { return ssn_; }
    const std::string& name() const { return name_; }
    void setSsn(std::uint32_t s) { ssn_ = s; }
    void setName(std::string n)  { name_ = std::move(n); }

    // ---- regions ---------------------------------------------------------

    RegionId addRegion(std::size_t size, std::size_t align = 8, std::string label = {}) {
        regions_.emplace_back(size, align, std::move(label));
        return static_cast<RegionId>(regions_.size() - 1);
    }
    Region&       region(RegionId id)       { return regions_.at(checked(id)); }
    const Region& region(RegionId id) const { return regions_.at(checked(id)); }
    std::size_t   regionCount() const       { return regions_.size(); }

    /// Region sized for `count` elements of `elemSize` bytes.
    RegionId addArrayRegion(std::size_t elemSize, std::size_t count,
                            std::string label = "array") {
        const std::size_t align = (elemSize && elemSize < 8) ? elemSize : 8;
        return addRegion(elemSize * count, align, std::move(label));
    }

    /// UTF-16 text plus a NUL terminator.
    RegionId addWideString(const std::u16string& s, std::string label = "wstr") {
        const RegionId r = addRegion((s.size() + 1) * 2, 2, std::move(label));
        if (!s.empty()) region(r).pokeBytes(0, s.data(), s.size() * 2);
        return r;
    }

    /// A UNICODE_STRING whose Buffer points at `text`. Length and MaximumLength are
    /// in BYTES - the field pair CVE-2020-0792 made inconsistent.
    RegionId addUnicodeString(const std::u16string& text,
                              std::string label = "UNICODE_STRING") {
        const RegionId buf = addWideString(text, label + ".Buffer");
        const RegionId us  = addRegion(16, 8, std::move(label));
        Region& R = region(us);
        R.poke<std::uint16_t>(0, static_cast<std::uint16_t>(text.size() * 2));
        R.poke<std::uint16_t>(2, static_cast<std::uint16_t>((text.size() + 1) * 2));
        R.pointerAt(8, buf);
        return us;
    }

    // ---- arguments -------------------------------------------------------

    void        setArgCount(std::size_t n) { args_.resize(n); }
    std::size_t argCount() const           { return args_.size(); }

    void setArg(std::size_t i, ArgValue v) {
        if (i >= args_.size()) args_.resize(i + 1);
        args_[i] = v;
    }
    ArgValue&       arg(std::size_t i)       { return args_.at(i); }
    const ArgValue& arg(std::size_t i) const { return args_.at(i); }

    // ---- marshalling -----------------------------------------------------

    /// Assign addresses, apply every relocation, and produce the ABI image.
    /// All addresses are assigned before any patching, so relocations may point
    /// forwards, backwards, or at themselves.
    ///
    /// This does NOT write the relocated addresses back into the frame. Baking them in
    /// would persist a simulated address into the region bytes, and from there into any
    /// corpus entry saved afterwards - a pointer field that should read as neutral would
    /// carry a stale address instead, and a later mutation that clears the relocation
    /// would turn it into a wild pointer nobody chose. The relocated bytes come back in
    /// MarshalledCall::memory instead, leaving the frame a pure description.
    MarshalledCall marshal(const Allocator& alloc) {
        if (!alloc) throw std::invalid_argument("marshal needs an allocator");

        for (Region& r : regions_)
            r.address = r.empty() ? 0 : alloc(r.size(), r.alignment);

        MarshalledCall m;
        m.memory.reserve(regions_.size());
        for (std::size_t i = 0; i < regions_.size(); ++i) {
            const Region& r = regions_[i];
            MarshalledCall::Image img;
            img.id = static_cast<RegionId>(i);
            img.address = r.address;
            img.bytes = r.bytes;
            for (const Reloc& rel : r.relocs) {
                if (rel.offset + 8 > img.bytes.size()) continue;
                const std::uint64_t base =
                    (rel.target == kNoRegion) ? 0 : regions_.at(checked(rel.target)).address;
                const std::uint64_t val =
                    base ? static_cast<std::uint64_t>(base + rel.addend) : 0;
                std::memcpy(img.bytes.data() + rel.offset, &val, sizeof(val));
            }
            m.memory.push_back(std::move(img));
        }
        m.ssn = ssn_;
        for (std::size_t i = 0; i < args_.size(); ++i) {
            const std::uint64_t v = resolve(args_[i]);
            switch (i) {
                case 0:  m.r10 = v; break;
                case 1:  m.rdx = v; break;
                case 2:  m.r8  = v; break;
                case 3:  m.r9  = v; break;
                default: m.stack.push_back(v); break;
            }
        }
        return m;
    }

    /// Total bytes that must be present in user memory before the call.
    std::size_t backingBytes() const {
        std::size_t n = 0;
        for (const Region& r : regions_) n += r.size();
        return n;
    }

private:
    std::size_t checked(RegionId id) const {
        if (id < 0 || static_cast<std::size_t>(id) >= regions_.size())
            throw std::out_of_range("region id " + std::to_string(id) + " out of range");
        return static_cast<std::size_t>(id);
    }

    std::uint64_t resolve(const ArgValue& a) const {
        switch (a.kind) {
            case ValueKind::Null:   return 0;
            case ValueKind::Scalar: return a.width == 4 ? (a.raw & 0xFFFF'FFFFull) : a.raw;
            case ValueKind::Handle:
            case ValueKind::RawPointer: return a.raw;
            case ValueKind::Pointer:
                if (a.region == kNoRegion) return 0;
                return static_cast<std::uint64_t>(regions_.at(checked(a.region)).address + a.offset);
        }
        return 0;
    }

    std::uint32_t         ssn_ = 0;
    std::string           name_;
    std::vector<Region>   regions_;
    std::vector<ArgValue> args_;
};

// =========================================== building a frame from metadata ==

struct BuildOptions {
    std::size_t    array_elements   = 8;       ///< elements for an array of unknown length
    std::size_t    opaque_size      = 0x40;    ///< size when no layout was recovered
    std::u16string string_text      = u"fuzz"; ///< initial content of string arguments
    bool           seed_constants   = true;    ///< write caller-observed constants (cbSize etc.)
    bool           seed_literals    = true;    ///< use an observed literal for scalars
    bool           back_nested_ptrs = true;    ///< give nested pointer fields real targets
};

/// Build a structurally well-formed CallFrame from a recovered prototype. This is the
/// starting point a mutator perturbs, not a valid call on its own: handles are left
/// zero, because no real handle is known at this level.
inline CallFrame buildFrame(const Syscall& s, const BuildOptions& opt = {}) {
    CallFrame f(s.ssn, s.name);
    f.setArgCount(static_cast<std::size_t>(s.nargs));
    std::vector<std::pair<int, std::size_t>> counts;   // applied after the main pass

    for (const Argument& a : s.args) {
        const auto        i     = static_cast<std::size_t>(a.index);
        const std::string label = "a" + std::to_string(i);

        // --- UNICODE_STRING ---
        if (a.character_data && a.character_data->form == "unicode_string_struct") {
            f.setArg(i, ArgValue::pointer(f.addUnicodeString(opt.string_text, label),
                                          Shape::String));
            continue;
        }

        // --- arrays ---
        if (a.kind == Kind::Array && a.array) {
            const std::size_t es =
                a.array->element_size ? static_cast<std::size_t>(*a.array->element_size) : 1;
            const int countArg = a.array->count_arg ? *a.array->count_arg : -1;
            const RegionId r   = f.addArrayRegion(es, opt.array_elements, label + "[]");
            f.setArg(i, ArgValue::array(r, static_cast<int>(es), countArg));
            // Defer writing the count: if it sits AFTER the buffer in the argument list
            // (NtDeviceIoControlFile: buffer a6, length a7) the loop would reach it later
            // and overwrite it with a plain zero scalar.
            if (countArg >= 0) counts.emplace_back(countArg, opt.array_elements);
            continue;
        }

        // --- other pointers ---
        if (a.isPointerLike()) {
            std::size_t sz = 0;
            if (a.pointee && a.pointee->size) sz = static_cast<std::size_t>(*a.pointee->size);
            if (sz == 0) sz = opt.opaque_size;  // nothing recovered: give the kernel something mapped
            const RegionId r = f.addRegion(sz, 8, label);

            if (a.pointee && opt.seed_constants)
                for (const Field& fld : a.pointee->fields)
                    if (fld.caller_const && fld.offset >= 0 &&
                        fld.offset + fld.size <= static_cast<int>(sz)) {
                        const auto v   = static_cast<std::uint64_t>(*fld.caller_const);
                        const auto off = static_cast<std::size_t>(fld.offset);
                        Region& R = f.region(r);
                        switch (fld.size) {
                            case 1: R.poke<std::uint8_t >(off, static_cast<std::uint8_t >(v)); break;
                            case 2: R.poke<std::uint16_t>(off, static_cast<std::uint16_t>(v)); break;
                            case 4: R.poke<std::uint32_t>(off, static_cast<std::uint32_t>(v)); break;
                            case 8: R.poke<std::uint64_t>(off, v); break;
                            default: break;  // wider than 8 bytes is a bulk copy, not a field
                        }
                    }

            if (a.pointee && opt.back_nested_ptrs)
                for (const NestedPointer& n : a.pointee->nested_pointers)
                    if (n.at_offset >= 0 && n.at_offset + 8 <= static_cast<int>(sz)) {
                        std::ostringstream lbl;
                        lbl << label << "+0x" << std::hex << n.at_offset;
                        const RegionId inner = f.addRegion(
                            n.size > 0 ? static_cast<std::size_t>(n.size) : 0x20, 8, lbl.str());
                        f.region(r).pointerAt(static_cast<std::size_t>(n.at_offset), inner);
                    }

            f.setArg(i, ArgValue::pointer(r, shapeOf(a)));
            continue;
        }

        // --- handles ---
        if (a.kind == Kind::Handle) { f.setArg(i, ArgValue::handle(0)); continue; }

        // --- scalars: prefer a literal the kernel was observed to accept ---
        std::uint64_t v = 0;
        if (opt.seed_literals && a.observed_values && !a.observed_values->literals.empty())
            v = static_cast<std::uint64_t>(a.observed_values->literals.front());
        f.setArg(i, ArgValue::scalar(v, a.size));
    }

    // Now that every argument exists, make each array's count match its buffer.
    for (const auto& [idx, n] : counts)
        if (idx >= 0 && static_cast<std::size_t>(idx) < f.argCount())
            f.setArg(static_cast<std::size_t>(idx), ArgValue::scalar(n, 4));
    return f;
}

inline CallFrame buildFrame(const Syscall& s, std::size_t elements) {
    BuildOptions o;
    o.array_elements = elements;
    return buildFrame(s, o);
}

// =============================================================== bound arg ==

/// An ArgValue paired with its recovered metadata. Answers "array or struct?" by
/// preferring the metadata and falling back to the value's own shape hint, then
/// exposes the mutations that make sense for whichever it turns out to be.
class BoundArg {
public:
    BoundArg(CallFrame& f, std::size_t i, const Argument* meta = nullptr)
        : f_(&f), i_(i), meta_(meta) {}

    std::size_t     index() const { return i_; }
    const Argument* meta()  const { return meta_; }
    /// The frame this argument belongs to - needed to resolve region ids when
    /// walking a pointer tree.
    CallFrame&       frame()       { return *f_; }
    const CallFrame& frame() const { return *f_; }
    ArgValue&       value()       { return f_->arg(i_); }
    const ArgValue& value() const { return f_->arg(i_); }

    Shape shape() const { return meta_ ? shapeOf(*meta_) : f_->arg(i_).shape; }

    bool isArray()  const { return shape() == Shape::Array;  }
    bool isStruct() const { return shape() == Shape::Struct; }
    bool isString() const { return shape() == Shape::String; }
    bool isScalar() const { return shape() == Shape::Scalar; }
    bool isHandle() const { return shape() == Shape::Handle; }
    /// A pointer whose contents were never recovered - mutate it as raw bytes.
    bool isOpaque() const { return shape() == Shape::Opaque; }

    // ---- raw bytes -------------------------------------------------------

    /// Pointer to the argument's backing bytes, or nullptr when there are none.
    ///
    /// Two things to know before using this:
    ///
    ///  * the bytes are PRE-RELOCATION. Pointer fields inside the region hold whatever
    ///    was last written there - zero in a freshly built frame - because addresses do
    ///    not exist until CallFrame::marshal() runs. Call marshal() first if you need
    ///    the buffer exactly as the kernel would see it.
    ///  * region() is null for a scalar or handle (the value is value().raw), and also
    ///    for a pointer that a mutation replaced with a literal address, because a
    ///    RawPointer has no region behind it.
    std::uint8_t* data() {
        Region* r = region();
        return (r && !r->empty()) ? r->bytes.data() : nullptr;
    }
    const std::uint8_t* data() const { return const_cast<BoundArg*>(this)->data(); }

    std::size_t byteCount() const {
        const Region* r = region();
        return r ? r->size() : 0;
    }

    /// Copy of the backing bytes; empty when the argument has no region.
    std::vector<std::uint8_t> bytes() const {
        const Region* r = region();
        return r ? r->bytes : std::vector<std::uint8_t>{};
    }

    /// The region a pointer FIELD at `offset` points at - for walking into a
    /// UNICODE_STRING's Buffer, or a nested structure. Null when that offset holds no
    /// relocation (including after setPointerFieldRaw dropped it).
    Region* pointeeAt(int offset) {
        Region* r = region();
        if (!r) return nullptr;
        for (const Reloc& rl : r->relocs)
            if (rl.offset == static_cast<std::size_t>(offset) && rl.target != kNoRegion)
                return &f_->region(rl.target);
        return nullptr;
    }

    /// Backing memory, or nullptr when this argument is not a pointer into the frame.
    Region* region() {
        ArgValue& v = f_->arg(i_);
        if (v.kind != ValueKind::Pointer || v.region == kNoRegion) return nullptr;
        return &f_->region(v.region);
    }
    const Region* region() const { return const_cast<BoundArg*>(this)->region(); }

    // ---- scalars and handles ---------------------------------------------

    void set(std::uint64_t v) {
        ArgValue& a = f_->arg(i_);
        a.raw = v;
        if (a.kind == ValueKind::Null || a.kind == ValueKind::Pointer) a.kind = ValueKind::Scalar;
    }
    void setNull() {
        ArgValue& a = f_->arg(i_); a.kind = ValueKind::Null; a.raw = 0;
    }
    void setRawPointer(std::uint64_t address) {
        ArgValue& a = f_->arg(i_); a.kind = ValueKind::RawPointer; a.raw = address;
    }

    // ---- arrays ----------------------------------------------------------

    int elementSize() const {
        if (meta_ && meta_->array && meta_->array->element_size) return *meta_->array->element_size;
        const int e = f_->arg(i_).elem_size;
        return e > 0 ? e : 1;
    }
    /// Index of the argument carrying the element count, or -1.
    int countArgIndex() const {
        if (meta_ && meta_->array && meta_->array->count_arg) return *meta_->array->count_arg;
        return f_->arg(i_).count_arg;
    }
    std::size_t elementCount() const {
        const Region* r = region();
        return r ? r->size() / static_cast<std::size_t>(elementSize()) : 0;
    }
    /// Resize the buffer AND update the count argument, so the two stay consistent.
    void setElementCount(std::size_t n) {
        requireRegion()->resize(n * static_cast<std::size_t>(elementSize()));
        writeCount(n);
    }
    /// Claim a count the buffer does not back - the integer-overflow shape.
    /// Returns false when no sibling argument carries the count.
    bool desyncCount(std::uint64_t claimed) {
        if (countArgIndex() < 0) return false;
        writeCount(claimed);
        return true;
    }
    template <typename T> T* elements() {
        Region* r = region(); return r ? r->as<T>() : nullptr;
    }
    template <typename T> const T* elements() const {
        const Region* r = region(); return r ? r->as<T>() : nullptr;
    }
    template <typename T> void setElement(std::size_t n, T v) {
        requireRegion()->poke<T>(n * sizeof(T), v);
    }

    // ---- structs ---------------------------------------------------------

    /// Recovered field layout; empty when nothing was recovered - poke by offset instead.
    const std::vector<Field>& fields() const {
        static const std::vector<Field> none;
        return (meta_ && meta_->pointee) ? meta_->pointee->fields : none;
    }
    const Field* fieldAt(int offset) const {
        for (const Field& f : fields())
            if (f.offset == offset) return &f;
        return nullptr;
    }
    /// True when the recovered "field" is a SIMD bulk copy rather than a scalar field.
    /// setField writes only its first 8 bytes; use region()->pokeBytes for the whole span.
    bool fieldIsBulk(int offset) const {
        const Field* f = fieldAt(offset);
        return f && f->size > 8;
    }
    void setField(int offset, std::uint64_t v, int size = 0) {
        Region* r = requireRegion();
        if (!size) { const Field* f = fieldAt(offset); size = f ? f->size : 8; }
        const auto off = static_cast<std::size_t>(offset);
        switch (size) {
            case 1: r->poke<std::uint8_t >(off, static_cast<std::uint8_t >(v)); break;
            case 2: r->poke<std::uint16_t>(off, static_cast<std::uint16_t>(v)); break;
            case 4: r->poke<std::uint32_t>(off, static_cast<std::uint32_t>(v)); break;
            default: r->poke<std::uint64_t>(off, v); break;  // >8: first 8 bytes only
        }
    }
    std::uint64_t getField(int offset, int size = 0) const {
        const Region* r = region();
        if (!r) return 0;
        if (!size) { const Field* f = fieldAt(offset); size = f ? f->size : 8; }
        const auto off = static_cast<std::size_t>(offset);
        switch (size) {
            case 1:  return r->peek<std::uint8_t >(off);
            case 2:  return r->peek<std::uint16_t>(off);
            case 4:  return r->peek<std::uint32_t>(off);
            default: return r->peek<std::uint64_t>(off);
        }
    }
    /// Offsets holding a pointer, so a mutator knows which fields need a real target.
    std::vector<std::size_t> pointerFieldOffsets() const {
        std::vector<std::size_t> out;
        if (const Region* r = region())
            for (const Reloc& rl : r->relocs) out.push_back(rl.offset);
        return out;
    }
    /// Repoint a pointer field at another region.
    void setPointerField(int offset, RegionId target, std::int64_t addend = 0) {
        requireRegion()->pointerAt(static_cast<std::size_t>(offset), target, addend);
    }
    /// Replace a pointer field with a literal address. Drops its relocation first,
    /// otherwise marshal() would overwrite the value.
    void setPointerFieldRaw(int offset, std::uint64_t address) {
        Region* r = requireRegion();
        r->clearPointerAt(static_cast<std::size_t>(offset));
        r->poke<std::uint64_t>(static_cast<std::size_t>(offset), address);
    }

    // ---- strings ---------------------------------------------------------

    /// UNICODE_STRING: Length and MaximumLength are in BYTES, not characters.
    void setUnicodeStringLengths(std::uint16_t length, std::uint16_t maximum) {
        setField(0, length, 2);
        setField(2, maximum, 2);
    }
    std::uint16_t unicodeLength()    const { return static_cast<std::uint16_t>(getField(0, 2)); }
    std::uint16_t unicodeMaxLength() const { return static_cast<std::uint16_t>(getField(2, 2)); }

private:
    Region* requireRegion() {
        if (Region* r = region()) return r;
        throw std::runtime_error("argument " + std::to_string(i_) + " has no backing region");
    }
    void writeCount(std::uint64_t n) {
        const int c = countArgIndex();
        if (c < 0) return;
        ArgValue cv = f_->arg(static_cast<std::size_t>(c));
        cv.kind = ValueKind::Scalar;
        cv.raw  = n;
        f_->setArg(static_cast<std::size_t>(c), cv);
    }

    CallFrame*      f_;
    std::size_t     i_;
    const Argument* meta_;
};

/// A CallFrame paired with the prototype it was built from.
class FrameView {
public:
    explicit FrameView(CallFrame& f, const Syscall* s = nullptr) : f_(&f), s_(s) {}

    /// Re-attach metadata to a frame that came back from JSON, which stores only ssn/name.
    static FrameView bind(CallFrame& f, const Database& db) {
        const Syscall* s = db.bySsn(f.ssn());
        if (!s && !f.name().empty()) s = db.byName(f.name());
        return FrameView(f, s);
    }

    CallFrame&     frame()           { return *f_; }
    std::size_t    size()      const { return f_->argCount(); }
    const Syscall* prototype() const { return s_; }
    bool           hasMetadata() const { return s_ != nullptr; }

    BoundArg operator[](std::size_t i) {
        const Argument* m = (s_ && i < s_->args.size()) ? &s_->args[i] : nullptr;
        return BoundArg(*f_, i, m);
    }

    /// Every argument of a given shape - the usual way to drive a mutator.
    std::vector<BoundArg> ofShape(Shape want) {
        std::vector<BoundArg> out;
        for (std::size_t i = 0; i < size(); ++i) {
            BoundArg b = (*this)[i];
            if (b.shape() == want) out.push_back(b);
        }
        return out;
    }

private:
    CallFrame*     f_;
    const Syscall* s_;
};

// ================================================================ json i/o ==

namespace detail {

inline const char* kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string b64encode(const std::vector<std::uint8_t>& in) {
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const std::uint32_t n = (std::uint32_t(in[i]) << 16) |
                                (std::uint32_t(in[i + 1]) << 8) | in[i + 2];
        out += kB64[(n >> 18) & 63]; out += kB64[(n >> 12) & 63];
        out += kB64[(n >>  6) & 63]; out += kB64[n & 63];
    }
    if (i < in.size()) {
        std::uint32_t n = std::uint32_t(in[i]) << 16;
        const bool two = (i + 1 < in.size());
        if (two) n |= std::uint32_t(in[i + 1]) << 8;
        out += kB64[(n >> 18) & 63];
        out += kB64[(n >> 12) & 63];
        out += two ? kB64[(n >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

inline std::vector<std::uint8_t> b64decode(const std::string& in) {
    const auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<std::uint8_t> out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        const int v = val(c);
        if (v < 0) throw std::runtime_error("invalid base64 in region bytes");
        acc = (acc << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

inline std::string hexencode(const std::vector<std::uint8_t>& in) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (std::uint8_t b : in) { out += d[b >> 4]; out += d[b & 15]; }
    return out;
}

inline std::vector<std::uint8_t> hexdecode(const std::string& in) {
    const auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    int hi = -1;
    for (char c : in) {
        if (c == ' ' || c == '\n' || c == '_') continue;
        const int v = nyb(c);
        if (v < 0) throw std::runtime_error("invalid hex in region bytes");
        if (hi < 0) hi = v;
        else { out.push_back(static_cast<std::uint8_t>((hi << 4) | v)); hi = -1; }
    }
    if (hi >= 0) throw std::runtime_error("odd number of hex digits in region bytes");
    return out;
}

}  // namespace detail

struct SerializeOptions {
    bool hex_bytes       = false;  ///< emit bytes_hex instead of bytes_b64 (diffs cleanly)
    bool elide_zero_fill = true;   ///< an all-zero region stores only its size
};

// ---- region ----

inline json toJson(const Region& r, const SerializeOptions& o = {}) {
    json j{{"label", r.label}, {"size", r.size()}, {"alignment", r.alignment}};
    if (r.isZero() && o.elide_zero_fill) j["zero_filled"] = true;
    else if (o.hex_bytes)                j["bytes_hex"]   = detail::hexencode(r.bytes);
    else                                 j["bytes_b64"]   = detail::b64encode(r.bytes);
    if (!r.relocs.empty()) {
        json a = json::array();
        for (const Reloc& rl : r.relocs) {
            json e{{"offset", rl.offset}, {"target", rl.target}};
            if (rl.addend) e["addend"] = rl.addend;
            a.push_back(std::move(e));
        }
        j["relocs"] = std::move(a);
    }
    return j;
}

inline Region regionFromJson(const json& j) {
    Region r;
    r.label     = j.value("label", std::string());
    r.alignment = j.value("alignment", std::size_t{8});
    const auto declared = j.value("size", std::size_t{0});

    if (j.contains("bytes_hex"))      r.bytes = detail::hexdecode(j.at("bytes_hex").get<std::string>());
    else if (j.contains("bytes_b64")) r.bytes = detail::b64decode(j.at("bytes_b64").get<std::string>());
    else                              r.bytes.assign(declared, 0);

    if (r.bytes.size() > declared)
        throw std::runtime_error("region '" + r.label + "': encoded bytes exceed declared size");
    r.bytes.resize(declared, 0);  // base64 padding can round up; the declared size wins

    if (auto it = j.find("relocs"); it != j.end())
        for (const auto& e : *it)
            r.relocs.push_back(Reloc{e.value("offset", std::size_t{0}),
                                     e.value("target", kNoRegion),
                                     e.value("addend", std::int64_t{0})});
    return r;
}

// ---- arg value ----

inline json toJson(const ArgValue& a) {
    json j{{"kind", valueKindName(a.kind)}, {"width", a.width}};
    if (a.shape != Shape::Unknown) j["shape"]        = shapeName(a.shape);
    if (a.elem_size)               j["element_size"] = a.elem_size;
    if (a.count_arg >= 0)          j["count_arg"]    = a.count_arg;
    switch (a.kind) {
        case ValueKind::Scalar:
        case ValueKind::Handle:
        case ValueKind::RawPointer: j["value"] = a.raw; break;
        case ValueKind::Pointer:
            j["region"] = a.region;
            if (a.offset) j["offset"] = a.offset;
            break;
        default: break;
    }
    return j;
}

inline ArgValue argValueFromJson(const json& j) {
    ArgValue a;
    a.kind      = valueKindFromName(j.value("kind", std::string("null")));
    a.width     = j.value("width", 8);
    a.raw       = j.value("value", std::uint64_t{0});
    a.region    = j.value("region", kNoRegion);
    a.offset    = j.value("offset", std::int64_t{0});
    a.shape     = shapeFromName(j.value("shape", std::string("unknown")));
    a.elem_size = j.value("element_size", 0);
    a.count_arg = j.value("count_arg", -1);
    return a;
}

// ---- marshalled call (a record of what was issued) ----

inline json toJson(const MarshalledCall& m) {
    return json{{"ssn", m.ssn}, {"r10", m.r10}, {"rdx", m.rdx}, {"r8", m.r8}, {"r9", m.r9},
                {"stack", m.stack},
                {"first_stack_offset", MarshalledCall::kFirstStackOffset}};
}

// ---- call frame ----

inline json toJson(const CallFrame& f, const SerializeOptions& o = {}) {
    json regions = json::array();
    for (std::size_t i = 0; i < f.regionCount(); ++i)
        regions.push_back(toJson(f.region(static_cast<RegionId>(i)), o));
    json args = json::array();
    for (std::size_t i = 0; i < f.argCount(); ++i)
        args.push_back(toJson(f.arg(i)));
    return json{{"format", "win32k.callframe"},
                {"version", kFrameFormatVersion},
                {"syscall", {{"name", f.name()}, {"ssn", f.ssn()}}},
                {"regions", std::move(regions)},
                {"args", std::move(args)}};
}

inline CallFrame callFrameFromJson(const json& j) {
    if (j.value("format", std::string()) != "win32k.callframe")
        throw std::runtime_error("not a win32k.callframe document");
    if (const int v = j.value("version", 0); v > kFrameFormatVersion)
        throw std::runtime_error("callframe version " + std::to_string(v) +
                                 " is newer than this build understands");

    const json sc = j.value("syscall", json::object());
    CallFrame f(sc.value("ssn", std::uint32_t{0}), sc.value("name", std::string()));

    for (const auto& rj : j.at("regions")) {
        Region r = regionFromJson(rj);
        const RegionId id = f.addRegion(r.size(), r.alignment, r.label);
        f.region(id).bytes  = std::move(r.bytes);
        f.region(id).relocs = std::move(r.relocs);
    }

    const std::size_t nregions = f.regionCount();
    const auto validRegion = [&](RegionId id) {
        return id == kNoRegion || (id >= 0 && static_cast<std::size_t>(id) < nregions);
    };

    // Validate here, rather than failing obscurely inside marshal().
    for (std::size_t i = 0; i < nregions; ++i) {
        const Region& r = f.region(static_cast<RegionId>(i));
        for (const Reloc& rl : r.relocs) {
            if (!validRegion(rl.target))
                throw std::runtime_error("region " + std::to_string(i) +
                                         " relocates to out-of-range region " +
                                         std::to_string(rl.target));
            if (rl.offset + 8 > r.size())
                throw std::runtime_error("region " + std::to_string(i) +
                                         " has a relocation past its end");
        }
    }

    const auto& aj = j.at("args");
    f.setArgCount(aj.size());
    for (std::size_t i = 0; i < aj.size(); ++i) {
        ArgValue v = argValueFromJson(aj[i]);
        if (v.kind == ValueKind::Pointer && !validRegion(v.region))
            throw std::runtime_error("argument " + std::to_string(i) +
                                     " points at out-of-range region " +
                                     std::to_string(v.region));
        f.setArg(i, v);
    }
    return f;
}

inline void saveFrame(const CallFrame& f, const std::string& path,
                      const SerializeOptions& o = {}, int indent = 1) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot write " + path);
    out << toJson(f, o).dump(indent) << '\n';
}

inline CallFrame loadFrame(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open " + path);
    json j;
    in >> j;
    return callFrameFromJson(j);
}

// ---- corpus ----

inline json toJson(const std::vector<CallFrame>& frames, const SerializeOptions& o = {}) {
    json a = json::array();
    for (const CallFrame& f : frames) a.push_back(toJson(f, o));
    return json{{"format", "win32k.corpus"},
                {"version", kFrameFormatVersion},
                {"count", frames.size()},
                {"frames", std::move(a)}};
}

inline std::vector<CallFrame> corpusFromJson(const json& j) {
    if (j.value("format", std::string()) != "win32k.corpus")
        throw std::runtime_error("not a win32k.corpus document");
    if (const int v = j.value("version", 0); v > kFrameFormatVersion)
        throw std::runtime_error("corpus version " + std::to_string(v) +
                                 " is newer than this build understands");
    std::vector<CallFrame> out;
    for (const auto& fj : j.at("frames")) out.push_back(callFrameFromJson(fj));
    return out;
}

inline void saveCorpus(const std::vector<CallFrame>& frames, const std::string& path,
                       const SerializeOptions& o = {}) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot write " + path);
    out << toJson(frames, o).dump(1) << '\n';
}

inline std::vector<CallFrame> loadCorpus(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open " + path);
    json j;
    in >> j;
    return corpusFromJson(j);
}

}  // namespace win32k::value