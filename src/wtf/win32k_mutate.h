// win32k_mutate.hpp - type-aware mutation of a CallFrame.
//
// Section VI-B1 of the NtFuzz paper: pick a mutation strategy from the argument's
// *type*, not from its bytes. The recovered database lets this go further than the
// paper did, in four places:
//
//   * observed literals   - arguments whose user-mode callers only ever pass a small
//                           set of values get that set as a dictionary, so a selector
//                           field can be walked instead of guessed.
//   * linked counts       - an array knows which argument carries its element count,
//                           so buffer and count can be desynchronised on purpose
//                           instead of by luck.
//   * caller constants    - a cbSize-style field seeded by user mode is mutated
//                           around its known-good value (size+-1, 0, huge).
//   * direction           - an out-parameter's pointee is kernel-written, so mutating
//                           its contents is wasted work; only its pointer is mutated.
//
// Handles are excluded by default, as in the paper: a bad HANDLE makes the syscall
// return an error immediately and the rest of the arguments are never reached.
//
// Every mutation is recorded in a MutationLog. That is what makes a crash
// reproducible and minimisable - without it a fuzzer finds bugs it cannot re-trigger.
#pragma once

#include "win32k_argvalue.h"
#include "mutator.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <random>
#include <string>
#include <vector>


namespace helpers {

constexpr bool DebugLoggingOn = false;
constexpr bool MutateSyscall = true;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (DebugLoggingOn) {
    fmt::print("Syscall: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}


std::vector<win32k::value::CallFrame> Deserialize(const uint8_t *Buffer, const size_t BufferSize) {
  const auto &Root = json::json::parse(Buffer, Buffer + BufferSize);
  try {
    return win32k::value::corpusFromJson(Root);
  } catch (std::runtime_error(what_arg)) {
    DebugPrint("{}\n", what_arg.what());
    return { win32k::value::callFrameFromJson(Root) };
  }
}

}

namespace win32k::mutate {

using namespace win32k::value;
using namespace helpers;

/// Deterministic and seedable on purpose: a fuzzing run must be replayable.
class Rng {
public:
    explicit Rng(std::uint64_t seed = 0x9E3779B97F4A7C15ull) : s_(seed ? seed : 1) {}

    std::uint64_t next() {          // splitmix64
        std::uint64_t z = (s_ += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    std::uint64_t below(std::uint64_t n) { return n ? next() % n : 0; }
    bool chance(double p)                { return p > 0.0 && (next() >> 11) * 0x1.0p-53 < p; }
    template <typename T> const T& pick(const std::vector<T>& v) { return v[below(v.size())]; }
    std::uint64_t seed() const { return s_; }

private:
    std::uint64_t s_;
};

/// Values that historically sit on the boundary of a check.
inline const std::vector<std::uint64_t>& interesting32() {
    static const std::vector<std::uint64_t> v{
        0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000,
        0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF};
    return v;
}


inline const std::vector<std::uint64_t>& interesting64() {
    static const std::vector<std::uint64_t> v{
        0, 1, 0xFFFFFFFFull, 0x100000000ull, 0x7FFFFFFFFFFFFFFFull,
        0x8000000000000000ull, 0xFFFFFFFFFFFFFFFFull};
    return v;
}
/// Addresses that probe the user/kernel split. 0x7FFFFFFF0000 is where win32k clamps
/// user pointers (MmUserProbeAddress); an odd address exercises the alignment checks
/// that raise ExRaiseDatatypeMisalignment.
inline const std::vector<std::uint64_t>& interestingPointers() {
    static const std::vector<std::uint64_t> v{
        0x0000000000000000ull,   // NULL
        0x0000000000000001ull,   // unaligned, non-null
        0x000000007FFF0000ull,   // 32-bit user boundary
        0x00007FFFFFFF0000ull,   // x64 MmUserProbeAddress
        0x00007FFFFFFFFFFFull,   // last user address
        0x0000800000000000ull,   // first non-canonical
        0xFFFF800000000000ull,   // kernel space
        0xFFFFFFFFFFFFFFFFull};
    return v;
}

struct MutationConfig {
    /// Per-candidate mutation probability. NtFuzz found 0.01 best on its corpus
    double probability        = 0.01;
    bool   mutate_handles     = false;  ///< a bad handle short-circuits the syscall
    bool   mutate_out_pointee = false;  ///< the kernel writes there; mutating it is wasted
    bool   mutate_pointers    = true;   ///< replace the pointer itself with a wild address
    bool   resize_arrays      = true;
    bool   desync_counts      = true;
    bool   use_dictionary     = true;   ///< prefer literals the kernel was seen to accept
    /// Ceiling on an array's SIZE, not its element count.
    ///
    /// A count is the wrong unit: the same number of elements is 50 bytes for a byte
    /// array and 3200 for a 64-byte one, and the arrays in the table span element sizes
    /// 1, 2, 4, 8, 16 and 64. Keep max_array_bytes in step with the writer's
    /// max_bytes_per_region - sizing past what the writer actually puts in the target
    /// produces bytes that are never written while setElementCount still raises the
    /// count argument, turning every resize into an accidental desync.
    std::size_t max_array_bytes    = 0x1000;
    std::size_t max_array_elements = 4096;  ///< absolute backstop, whichever binds first
    std::size_t max_mutations      = 16; ///< cap per frame, so one call stays explainable
};

/// Choose an element count worth trying.
/// This mixes boundaries, the neighbourhood of the count the call already had, and a
/// log-uniform spread, so every magnitude stays reachable and zero appears ~6% of the
/// time.
inline std::size_t pickElementCount(Rng& rng, std::size_t current, std::size_t cap) {
    if (cap < 1) cap = 1;
    const std::uint64_t roll = rng.below(100);
    if (roll < 25) {                       // boundaries, including zero
        static const std::vector<std::uint64_t> edge{0, 1, 2, 3};
        return static_cast<std::size_t>(std::min<std::uint64_t>(rng.pick(edge), cap));
    }
    if (roll < 50 && current) {            // just off what the call already had
        static const std::vector<std::int64_t> d{-2, -1, 1, 2};
        const std::int64_t n = static_cast<std::int64_t>(current) + rng.pick(d);
        return static_cast<std::size_t>(
            std::clamp<std::int64_t>(n, 0, static_cast<std::int64_t>(cap)));
    }
    if (roll < 90) {                       // log-uniform: every magnitude equally likely
        std::size_t bits = 0;
        while ((std::size_t{1} << (bits + 1)) <= cap && bits < 31) ++bits;
        const std::size_t mag = static_cast<std::size_t>(rng.below(bits + 1));
        const std::size_t hi  = std::min<std::size_t>(std::size_t{1} << mag, cap);
        return static_cast<std::size_t>(rng.below(hi)) + 1;
    }
    return cap;                            // and the ceiling itself
}

/// The paper's variable-probability strategy: p = 0.01 * 2^n, n in [-3, 3].
inline double pickProbability(Rng& rng) {
    static const std::array<double, 7> ps{0.00125, 0.0025, 0.005, 0.01, 0.02, 0.04, 0.08};
    return ps[rng.below(ps.size())];
}

// ==================================================================== log ==

enum class Strategy {
    ScalarBitFlip, ScalarArithmetic, ScalarInteresting, ScalarDictionary, ScalarRandom,
    StructField, StructSizeField, StructPointerField,
    ArrayElement, ArrayResize, ArrayCountDesync,
    StringLength, StringBuffer, StringContent,
    PointerWild, PointerNull, PointerUnaligned,
    OpaqueBytes
};

inline const char* strategyName(Strategy s) {
    switch (s) {
        case Strategy::ScalarBitFlip:      return "scalar.bitflip";
        case Strategy::ScalarArithmetic:   return "scalar.arith";
        case Strategy::ScalarInteresting:  return "scalar.interesting";
        case Strategy::ScalarDictionary:   return "scalar.dictionary";
        case Strategy::ScalarRandom:       return "scalar.random";
        case Strategy::StructField:        return "struct.field";
        case Strategy::StructSizeField:    return "struct.size_field";
        case Strategy::StructPointerField: return "struct.pointer_field";
        case Strategy::ArrayElement:       return "array.element";
        case Strategy::ArrayResize:        return "array.resize";
        case Strategy::ArrayCountDesync:   return "array.count_desync";
        case Strategy::StringLength:       return "string.length";
        case Strategy::StringBuffer:       return "string.buffer";
        case Strategy::StringContent:      return "string.content";
        case Strategy::PointerWild:        return "pointer.wild";
        case Strategy::PointerNull:        return "pointer.null";
        case Strategy::PointerUnaligned:   return "pointer.unaligned";
        case Strategy::OpaqueBytes:        return "opaque.bytes";
    }
    return "?";
}

struct MutationRecord {
    std::size_t arg = 0;
    Strategy    strategy = Strategy::ScalarRandom;
    int         offset = -1;        ///< field/element offset, -1 when not applicable
    std::uint64_t before = 0, after = 0;
    std::string detail;

    std::string describe() const {
        std::ostringstream o;
        o << "a" << arg << ' ' << strategyName(strategy);
        if (offset >= 0) o << " +0x" << std::hex << offset << std::dec;
        o << ": 0x" << std::hex << before << " -> 0x" << after << std::dec;
        if (!detail.empty()) o << "  (" << detail << ')';
        return o.str();
    }
};

struct MutationLog {
    std::uint64_t               seed = 0;
    double                      probability = 0;
    std::vector<MutationRecord> records;

    bool empty() const { return records.empty(); }
    json toJson() const {
        json a = json::array();
        for (const auto& r : records)
            a.push_back(json{{"arg", r.arg}, {"strategy", strategyName(r.strategy)},
                             {"offset", r.offset}, {"before", r.before}, {"after", r.after},
                             {"detail", r.detail}});
        return json{{"seed", seed}, {"probability", probability}, {"mutations", std::move(a)}};
    }
};

// ================================================================ mutator ==

class CustomMutator_t : public Mutator_t {
private:
    std::unique_ptr<uint8_t[]> ScratchBuffer__;
    span_u8 ScratchBuffer_;
    size_t TestcaseMaxSize_ = 0;

    win32k::Database SyscallDatabase_;

    Rng            rng_;
    MutationConfig cfg_;
    MutationLog    log_;
    FrameView*     view_ = nullptr;   ///< set for the duration of mutate(), to read siblings

public:
    static std::unique_ptr<Mutator_t> Create(std::mt19937_64 &Rng, const size_t TestcaseMaxSize) {
        return std::make_unique<CustomMutator_t>(Rng, TestcaseMaxSize);
    }

    explicit CustomMutator_t(std::mt19937_64 &rng, const size_t TestcaseMaxSize, MutationConfig cfg = {})
      : rng_(rng()), TestcaseMaxSize_(TestcaseMaxSize), cfg_(cfg) {
        ScratchBuffer__ = std::make_unique<uint8_t[]>(_1MB);
        ScratchBuffer_ = {ScratchBuffer__.get(), _1MB};

        try {
            SyscallDatabase_ = win32k::Database::fromFile("win32k_syscalls_26100.json");
 
            std::cout << "schema " << SyscallDatabase_.schemaVersion()
                    << "   build " << SyscallDatabase_.build().value("build", "?")
                    << "   " << SyscallDatabase_.syscalls().size() << " syscall(s)\n\n";

        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
        }
    }

    const MutationConfig& config() const { return cfg_; }
    MutationConfig&       config()       { return cfg_; }

    std::string GetNewTestcase(const Corpus_t &Corpus) override {
        const Testcase_t *Testcase = Corpus.PickTestcase();
        if (!Testcase) {
            fmt::print("The corpus is empty, exiting\n");
            std::abort();
        }

        //
        // Copy the input in a buffer we're going to mutate.
        //
        memcpy(ScratchBuffer_.data(), Testcase->Buffer_.get(), Testcase->BufferSize_);
        return Mutate(ScratchBuffer_.data(), Testcase->BufferSize_, ScratchBuffer_.size_bytes());
    }


    std::string Mutate(uint8_t *Data, const size_t DataLen, const size_t MaxSize) {
        std::vector<CallFrame> Root = Deserialize(Data, DataLen);
        DebugPrint("Mutate: {} packets\n", Root.size());

        for(auto& frame : Root){
            FrameView fw = FrameView::bind(frame, SyscallDatabase_);
            MutationLog logs{ mutateWithVariableProbability(fw) };
            // std::cout << logs.toJson() << "\n";
        }

        json Serialized{ win32k::value::toJson(Root) };
        return Serialized.dump();
    }

    /// Mutate a frame in place. Returns what was done, so the case can be replayed
    /// and minimised. An empty log means the frame was left untouched, which at a
    /// low probability is the common outcome and is not an error.
    MutationLog mutate(FrameView& view) {
        view_ = &view;
        log_ = MutationLog{};
        log_.seed        = rng_.seed();
        log_.probability = cfg_.probability;

        for (std::size_t i = 0; i < view.size(); ++i) {
            if (log_.records.size() >= cfg_.max_mutations) break;
            BoundArg a = view[i];

            switch (a.shape()) {
                case Shape::Handle:  if (cfg_.mutate_handles) mutateScalar(a); break;
                case Shape::Scalar:  mutateScalar(a);  break;
                case Shape::Array:   mutateArray(a);   break;
                case Shape::Struct:  mutateStruct(a);  break;
                case Shape::String:  mutateString(a);  break;
                case Shape::Opaque:  mutateOpaque(a);  break;
                case Shape::Unknown:
                default:             mutateScalar(a);  break;  // width-only: treat as an integer
            }
        }

        view_ = nullptr;
        return log_;
    }

    /// One round with a freshly chosen probability, as the paper does per execution.
    MutationLog mutateWithVariableProbability(FrameView& view) {
        cfg_.probability = pickProbability(rng_);
        return mutate(view);
    }

private:
    void mutateScalar(BoundArg& a) {
        if (!rng_.chance(cfg_.probability)) return;
        ArgValue& v = a.value();
        const std::uint64_t before = v.raw;
        const int width = v.width == 4 ? 4 : 8;

        // The dictionary is only useful when the callers really were constrained.
        const std::vector<std::int64_t>* dict = nullptr;
        if (cfg_.use_dictionary && a.meta() && a.meta()->observed_values &&
            !a.meta()->observed_values->literals.empty())
            dict = &a.meta()->observed_values->literals;

        Strategy how;
        std::uint64_t out = before;
        switch (rng_.below(dict ? 5 : 4)) {
            case 0: {
                how = Strategy::ScalarBitFlip;
                out = before ^ (1ull << rng_.below(static_cast<std::uint64_t>(width) * 8));
                break;
            }
            case 1: {
                how = Strategy::ScalarArithmetic;
                const std::int64_t d = static_cast<std::int64_t>(rng_.below(70)) - 35;
                out = before + static_cast<std::uint64_t>(d);
                break;
            }
            case 2:
                how = Strategy::ScalarInteresting;
                out = rng_.pick(width == 4 ? interesting32() : interesting64());
                break;
            case 3:
                how = Strategy::ScalarRandom;
                out = rng_.next();
                break;
            default:
                how = Strategy::ScalarDictionary;
                out = static_cast<std::uint64_t>(rng_.pick(*dict));
                break;
        }
        if (width == 4) out &= 0xFFFFFFFFull;
        v.raw  = out;
        v.kind = ValueKind::Scalar;
        record(a.index(), how, -1, before, out);
    }


    void mutateArray(BoundArg& a) {
        Region* r = a.region();
        if (!r) { mutatePointerValue(a); return; }
        const int es = a.elementSize();

        // Resize FIRST: setElementCount rewrites the count argument to match, so doing
        // it after a desync would silently undo the desync.
        if (cfg_.resize_arrays && rng_.chance(cfg_.probability)) {
            const std::size_t oldN = a.elementCount();
            const std::size_t per  = static_cast<std::size_t>(std::max(es, 1));
            // Whichever ceiling binds first, plus the testcase budget: base64 costs
            // about 4/3 of a character per byte once the document is dumped.
            std::size_t cap = std::min(cfg_.max_array_bytes / per, cfg_.max_array_elements);
            if (TestcaseMaxSize_)
                cap = std::min(cap,
                               std::max<std::size_t>(1, (TestcaseMaxSize_ * 3 / 4) / per));
            const std::size_t newN = pickElementCount(rng_, oldN, std::max<std::size_t>(cap, 1));
            a.setElementCount(newN);
            record(a.index(), Strategy::ArrayResize, -1, oldN, newN);
        }

        // Desynchronising the count from the buffer is the whole point of knowing
        // which argument the count lives in.
        if (cfg_.desync_counts && a.countArgIndex() >= 0 && rng_.chance(cfg_.probability)) {
            const auto ci = static_cast<std::size_t>(a.countArgIndex());
            const std::uint64_t before = view_ ? view_->frame().arg(ci).raw : 0;
            const std::uint64_t claimed = rng_.pick(interesting32());
            if (a.desyncCount(claimed))
                record(a.index(), Strategy::ArrayCountDesync, -1, before, claimed,
                       "count in a" + std::to_string(a.countArgIndex()) +
                       ", buffer holds " + std::to_string(a.elementCount()));
        }

        // Element-wise, as the paper describes: walk the array rather than only the head.
        const std::size_t n = a.elementCount();
        for (std::size_t k = 0; k < n; ++k) {
            if (log_.records.size() >= cfg_.max_mutations) break;
            if (!rng_.chance(cfg_.probability)) continue;
            const std::size_t off = k * static_cast<std::size_t>(es);
            const std::uint64_t before = readAt(*r, off, es);
            const std::uint64_t after  = rng_.pick(es <= 4 ? interesting32() : interesting64());
            writeAt(*r, off, es, after);
            record(a.index(), Strategy::ArrayElement, static_cast<int>(off), before, after,
                   "element " + std::to_string(k));
        }
        mutatePointerValue(a);
    }


    void mutateStruct(BoundArg& a) {
        Region* r = a.region();
        if (!r) { mutatePointerValue(a); return; }

        const bool isOut = a.meta() && a.meta()->direction != Direction::In;
        if (isOut && !cfg_.mutate_out_pointee) { mutatePointerValue(a); return; }

        for (const Field& f : a.fields()) {
            if (log_.records.size() >= cfg_.max_mutations) break;
            if (f.offset < 0 || f.offset + f.size > static_cast<int>(r->size())) continue;
            if (!rng_.chance(cfg_.probability)) continue;

            const int size = f.size > 8 ? 8 : f.size;   // >8 is a bulk copy, not a field
            const auto off = static_cast<std::size_t>(f.offset);
            const std::uint64_t before = readAt(*r, off, size);

            // A field user mode seeds with a constant is a size/version field: the
            // interesting values sit next to the known-good one, not at random.
            if (f.caller_const) {
                const std::uint64_t k = static_cast<std::uint64_t>(*f.caller_const);
                const std::vector<std::uint64_t> around{k - 1, k + 1, 0, ~0ull,
                                                        k << 1, 0x7FFFFFFF};
                const std::uint64_t after = rng_.pick(around);
                writeAt(*r, off, size, after);
                record(a.index(), Strategy::StructSizeField, f.offset, before, after,
                       "caller writes " + std::to_string(k));
                continue;
            }
            const std::uint64_t after = rng_.pick(size <= 4 ? interesting32() : interesting64());
            writeAt(*r, off, size, after);
            record(a.index(), Strategy::StructField, f.offset, before, after,
                   std::string(f.access) + ", " + std::to_string(f.size) + " bytes");
        }

        // Nested pointers: the double-fetch surface. Point them somewhere hostile.
        for (std::size_t off : a.pointerFieldOffsets()) {
            if (log_.records.size() >= cfg_.max_mutations) break;
            if (!rng_.chance(cfg_.probability)) continue;
            const std::uint64_t wild = rng_.pick(interestingPointers());
            a.setPointerFieldRaw(static_cast<int>(off), wild);
            record(a.index(), Strategy::StructPointerField, static_cast<int>(off), 0, wild,
                   "nested pointer repointed");
        }
        mutatePointerValue(a);
    }


    void mutateString(BoundArg& a) {
        Region* r = a.region();
        if (!r) { mutatePointerValue(a); return; }

        const bool isUnicodeString =
            a.meta() && a.meta()->character_data &&
            a.meta()->character_data->form == "unicode_string_struct";

        if (isUnicodeString && r->size() >= 16) {
            // Buffer that matches neither.
            if (rng_.chance(cfg_.probability)) {
                const std::uint16_t before = a.unicodeLength();
                const std::vector<std::uint64_t> lengths{
                    0, 1, 0x101, 0xFFFF, 0xFFFE,
                    static_cast<std::uint64_t>(a.unicodeMaxLength() + 2)};
                const auto after = static_cast<std::uint16_t>(rng_.pick(lengths));
                a.setUnicodeStringLengths(after, a.unicodeMaxLength());
                record(a.index(), Strategy::StringLength, 0, before, after,
                       (after & 1) ? "odd byte length" : "length vs maximum");
            }
            if (rng_.chance(cfg_.probability)) {
                const std::uint64_t wild = rng_.pick(interestingPointers());
                a.setPointerFieldRaw(8, wild);
                record(a.index(), Strategy::StringBuffer, 8, 0, wild, "Buffer repointed");
            }
            mutatePointerValue(a);
            return;
        }

        // A counted or NUL-terminated character buffer: truncate, extend, or corrupt.
        if (rng_.chance(cfg_.probability)) {
            const std::size_t n = r->size();
            const std::size_t at = rng_.below(n ? n : 1);
            const std::uint64_t before = n ? r->peek<std::uint8_t>(at) : 0;
            const auto after = static_cast<std::uint8_t>(rng_.next());
            if (n) r->poke<std::uint8_t>(at, after);
            record(a.index(), Strategy::StringContent, static_cast<int>(at), before, after);
        }
        mutatePointerValue(a);
    }


    void mutateOpaque(BoundArg& a) {
        Region* r = a.region();
        if (!r || r->empty()) { mutatePointerValue(a); return; }
        if (rng_.chance(cfg_.probability)) {
            const std::size_t at = rng_.below(r->size());
            const std::uint64_t before = r->peek<std::uint8_t>(at);
            const auto after = static_cast<std::uint8_t>(rng_.next());
            r->poke<std::uint8_t>(at, after);
            record(a.index(), Strategy::OpaqueBytes, static_cast<int>(at), before, after,
                   "no layout recovered");
        }
        mutatePointerValue(a);
    }


    void mutatePointerValue(BoundArg& a) {
        if (!cfg_.mutate_pointers) return;
        if (a.value().kind != ValueKind::Pointer && a.value().kind != ValueKind::RawPointer) return;
        if (!rng_.chance(cfg_.probability)) return;

        const std::uint64_t wild = rng_.pick(interestingPointers());
        Strategy how = Strategy::PointerWild;
        if (wild == 0)      how = Strategy::PointerNull;
        else if (wild & 1)  how = Strategy::PointerUnaligned;
        a.setRawPointer(wild);
        record(a.index(), how, -1, 0, wild, "argument pointer replaced");
    }

    // ---- helpers ----------------------------------------------------------

    static std::uint64_t readAt(const Region& r, std::size_t off, int size) {
        switch (size) {
            case 1:  return r.peek<std::uint8_t >(off);
            case 2:  return r.peek<std::uint16_t>(off);
            case 4:  return r.peek<std::uint32_t>(off);
            default: return r.peek<std::uint64_t>(off);
        }
    }
    static void writeAt(Region& r, std::size_t off, int size, std::uint64_t v) {
        switch (size) {
            case 1: r.poke<std::uint8_t >(off, static_cast<std::uint8_t >(v)); break;
            case 2: r.poke<std::uint16_t>(off, static_cast<std::uint16_t>(v)); break;
            case 4: r.poke<std::uint32_t>(off, static_cast<std::uint32_t>(v)); break;
            default: r.poke<std::uint64_t>(off, v); break;
        }
    }
    void record(std::size_t arg, Strategy s, int off,
                std::uint64_t before, std::uint64_t after, std::string detail = {}) {

        log_.records.push_back(MutationRecord{arg, s, off, before, after, std::move(detail)});
    }
};

}  // namespace win32k::mutate
