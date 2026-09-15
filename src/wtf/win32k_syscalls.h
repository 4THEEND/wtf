// win32k_syscalls.hpp - typed reader for win32k_syscalls_26100.json (schema 2.0)
//
//   #include "win32k_syscalls.hpp"
//   auto db = win32k::Database::fromFile("win32k_syscalls_26100.json");
//   const auto* s = db.byName("NtUserSetWindowPos");
//   for (const auto& a : s->args)
//       std::cout << a.index << ' ' << a.c_type << ' ' << a.location.describe() << '\n';
//
// Requires nlohmann/json >= 3.11 and C++17. Header-only, no other dependencies.
#pragma once

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace win32k {

using nlohmann::json;

// ---------------------------------------------------------------- enums ----

enum class Kind { Handle, Scalar, Pointer, Buffer, Array, String, Unknown };
enum class Direction { In, Out, InOut };
enum class Confidence { Low, Medium, High };
enum class LocClass { Register, Stack };

inline Kind kindFromString(const std::string& s) {
    if (s == "handle")  return Kind::Handle;
    if (s == "scalar")  return Kind::Scalar;
    if (s == "pointer") return Kind::Pointer;
    if (s == "buffer")  return Kind::Buffer;
    if (s == "array")   return Kind::Array;
    if (s == "string")  return Kind::String;
    return Kind::Unknown;
}
inline const char* toString(Kind k) {
    switch (k) {
        case Kind::Handle:  return "handle";
        case Kind::Scalar:  return "scalar";
        case Kind::Pointer: return "pointer";
        case Kind::Buffer:  return "buffer";
        case Kind::Array:   return "array";
        case Kind::String:  return "string";
        default:            return "unknown";
    }
}
inline Direction directionFromString(const std::string& s) {
    if (s == "out")   return Direction::Out;
    if (s == "inout") return Direction::InOut;
    return Direction::In;
}
inline const char* toString(Direction d) {
    switch (d) {
        case Direction::Out:   return "out";
        case Direction::InOut: return "inout";
        default:               return "in";
    }
}
inline Confidence confidenceFromString(const std::string& s) {
    if (s == "high")   return Confidence::High;
    if (s == "medium") return Confidence::Medium;
    return Confidence::Low;
}
inline const char* toString(Confidence c) {
    switch (c) {
        case Confidence::High:   return "high";
        case Confidence::Medium: return "medium";
        default:                 return "low";
    }
}

// ---------------------------------------------------------------- types ----

/// One field of a structure a pointer argument points at.
struct Field {
    int         offset = 0;
    int         size   = 0;          ///< bytes
    std::string access;              ///< "r", "w" or "rw"
    std::string c_type;
    std::optional<std::int64_t> caller_const;  ///< value a user-mode caller writes here
    std::optional<std::string>  name;          ///< only for known structs (UNICODE_STRING)

    bool isRead()  const { return access.find('r') != std::string::npos; }
    bool isWritten() const { return access.find('w') != std::string::npos; }
};

/// A pointer field inside the pointee, followed one level further.
struct NestedPointer {
    int                at_offset = 0;
    int                size      = 0;
    std::vector<Field> fields;
};

/// What a pointer / buffer / string / array argument points at.
struct Pointee {
    std::optional<int>         size;         ///< bytes; absent when not recovered
    std::optional<std::string> struct_name;  ///< e.g. "UNICODE_STRING"
    std::vector<Field>         fields;
    std::vector<NestedPointer> nested_pointers;
};

struct ArrayInfo {
    std::optional<int> element_size;
    std::string        element_c_type;
    std::optional<int> count_arg;    ///< index into Syscall::args holding the element count
    bool               count_known = false;
};

struct CharacterData {
    std::string        encoding;     ///< "utf-16le" | "ansi"
    std::string        form;         ///< nul_terminated | counted_array
                                     ///< | unicode_string_struct | ansi_string_struct
    std::optional<int> count_arg;
    int                element_size = 0;
    std::optional<std::string> detail;

    bool isWide()    const { return encoding == "utf-16le"; }
    bool isCounted() const { return form != "nul_terminated"; }
};

struct ObservedValues {
    std::vector<std::int64_t> literals;   ///< every literal seen at user-mode call sites
    int                       call_sites = 0;
};

/// Machine-readable provenance for one inference. `raw` keeps any extra keys.
struct Evidence {
    std::string source;   ///< "kernel" | "user_mode"
    std::string kind;     ///< probe_read, array_bound, gdi_object_lock, ...
    json        raw;

    bool fromKernel()   const { return source == "kernel"; }
    bool fromUserMode() const { return source == "user_mode"; }
};

/// Where the caller must place the argument.
struct Location {
    LocClass    cls = LocClass::Register;
    std::string syscall_register;   ///< register the kernel reads (a0 is R10, not RCX)
    std::string stub_register;      ///< register to load when calling the win32u stub
    std::optional<int> stack_offset;///< from RSP at the SYSCALL instruction
    int         slot_size = 8;

    bool isRegister() const { return cls == LocClass::Register; }

    std::string describe() const {
        if (isRegister()) {
            if (stub_register != syscall_register)
                return syscall_register + " (load " + stub_register + " for the stub)";
            return syscall_register;
        }
        std::ostringstream o;
        o << "[RSP+0x" << std::hex << stack_offset.value_or(0) << "]";
        return o.str();
    }
};

struct Argument {
    int         index = 0;
    Kind        kind  = Kind::Unknown;
    std::string c_type;          ///< ULONG_PTR on an unresolved arg means "unknown 64-bit"
    int         size = 8;        ///< size of the argument itself (4 or 8)
    Direction   direction = Direction::In;
    Confidence  confidence = Confidence::Low;
    bool        resolved = false;///< false => width-only guesswork
    std::string c_decl;
    std::string note;
    Location    location;

    std::optional<Pointee>        pointee;
    std::optional<ArrayInfo>      array;
    std::optional<CharacterData>  character_data;
    std::optional<ObservedValues> observed_values;
    std::vector<Evidence>         evidence;

    bool isPointerLike() const {
        return kind == Kind::Pointer || kind == Kind::Buffer ||
               kind == Kind::Array   || kind == Kind::String;
    }
    bool isOutput() const { return direction != Direction::In; }
    bool hasEvidence(const std::string& k) const {
        return std::any_of(evidence.begin(), evidence.end(),
                           [&](const Evidence& e) { return e.kind == k; });
    }
};

struct Implementation {
    std::optional<std::string>   module;   ///< win32kfull | win32kbase | dxgkrnl
    std::optional<std::uint64_t> rva;
};

struct Dispatch {
    std::string                  kind;     ///< "apiset" | "import_thunk"
    std::optional<int>           table_offset;
    std::optional<int>           slot;
    std::optional<std::string>   subtable_module;
    std::optional<std::uint64_t> subtable_rva;
    bool                         resolved = false;
};

struct UserMode {
    std::vector<std::string> one_to_one_thunk_apis;  ///< prototype == that API's prototype
    std::vector<std::string> calling_apis;
    bool                     reachable_from_user_api = false;
};

struct Syscall {
    std::uint32_t         ssn = 0;      ///< 0x1000 + index
    int                   index = 0;
    std::string           name;
    int                   nargs = 0;
    std::string           c_prototype;
    Implementation        implementation;
    Dispatch              dispatch;
    UserMode              user_mode;
    std::vector<Argument> args;

    /// Element-count argument for an array argument, or nullptr.
    const Argument* countArgFor(const Argument& a) const {
        if (!a.array || !a.array->count_arg) return nullptr;
        int i = *a.array->count_arg;
        return (i >= 0 && i < static_cast<int>(args.size())) ? &args[i] : nullptr;
    }
};

// ------------------------------------------------------- json -> structs ---
// Written by hand rather than with the macros: most fields are optional and the
// macros would throw on a document that legitimately omits them.

namespace detail {
template <typename T>
std::optional<T> opt(const json& j, const char* key) {
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) return std::nullopt;
    return it->get<T>();
}
/// json::value() only falls back when the key is ABSENT; a key present with a
/// null value still throws. The document uses null for "not applicable"
/// (e.g. syscall_register on a stack argument), so go through this instead.
template <typename T>
T get(const json& j, const char* key, T fallback) {
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) return fallback;
    return it->get<T>();
}
}  // namespace detail

inline void from_json(const json& j, Field& f) {
    f.offset = detail::get<int>(j, "offset", 0);
    f.size   = detail::get<int>(j, "size", 0);
    f.access = detail::get<std::string>(j, "access", std::string("r"));
    f.c_type = detail::get<std::string>(j, "c_type", std::string());
    f.caller_const = detail::opt<std::int64_t>(j, "caller_const");
    f.name         = detail::opt<std::string>(j, "name");
}

inline void from_json(const json& j, NestedPointer& n) {
    n.at_offset = detail::get<int>(j, "at_offset", 0);
    n.size      = detail::get<int>(j, "size", 0);
    if (auto it = j.find("fields"); it != j.end()) n.fields = it->get<std::vector<Field>>();
}

inline void from_json(const json& j, Pointee& p) {
    p.size        = detail::opt<int>(j, "size");
    p.struct_name = detail::opt<std::string>(j, "struct_name");
    if (auto it = j.find("fields"); it != j.end()) p.fields = it->get<std::vector<Field>>();
    if (auto it = j.find("nested_pointers"); it != j.end())
        p.nested_pointers = it->get<std::vector<NestedPointer>>();
}

inline void from_json(const json& j, ArrayInfo& a) {
    a.element_size   = detail::opt<int>(j, "element_size");
    a.element_c_type = detail::get<std::string>(j, "element_c_type", std::string());
    a.count_arg      = detail::opt<int>(j, "count_arg");
    a.count_known    = detail::get<bool>(j, "count_known", false);
}

inline void from_json(const json& j, CharacterData& c) {
    c.encoding     = detail::get<std::string>(j, "encoding", std::string());
    c.form         = detail::get<std::string>(j, "form", std::string());
    c.count_arg    = detail::opt<int>(j, "count_arg");
    c.element_size = detail::get<int>(j, "element_size", 0);
    c.detail       = detail::opt<std::string>(j, "detail");
}

inline void from_json(const json& j, ObservedValues& o) {
    if (auto it = j.find("literals"); it != j.end())
        o.literals = it->get<std::vector<std::int64_t>>();
    o.call_sites = detail::get<int>(j, "call_sites", 0);
}

inline void from_json(const json& j, Evidence& e) {
    e.source = detail::get<std::string>(j, "source", std::string());
    e.kind   = detail::get<std::string>(j, "kind", std::string());
    e.raw    = j;
}

inline void from_json(const json& j, Location& l) {
    l.cls = (detail::get<std::string>(j, "class", std::string("register")) == "stack") ? LocClass::Stack
                                                                  : LocClass::Register;
    l.syscall_register = detail::get<std::string>(j, "syscall_register", std::string());
    l.stub_register    = detail::get<std::string>(j, "stub_register", std::string());
    l.stack_offset     = detail::opt<int>(j, "stack_offset");
    l.slot_size        = detail::get<int>(j, "slot_size", 8);
}

inline void from_json(const json& j, Argument& a) {
    a.index      = detail::get<int>(j, "index", 0);
    a.kind       = kindFromString(detail::get<std::string>(j, "kind", std::string("unknown")));
    a.c_type     = detail::get<std::string>(j, "c_type", std::string());
    a.size       = detail::get<int>(j, "size", 8);
    a.direction  = directionFromString(detail::get<std::string>(j, "direction", std::string("in")));
    a.confidence = confidenceFromString(detail::get<std::string>(j, "confidence", std::string("low")));
    a.resolved   = detail::get<bool>(j, "resolved", false);
    a.c_decl     = detail::get<std::string>(j, "c_decl", std::string());
    a.note       = detail::get<std::string>(j, "note", std::string());
    if (auto it = j.find("location");        it != j.end()) a.location = it->get<Location>();
    if (auto it = j.find("pointee");         it != j.end()) a.pointee = it->get<Pointee>();
    if (auto it = j.find("array");           it != j.end()) a.array = it->get<ArrayInfo>();
    if (auto it = j.find("character_data");  it != j.end()) a.character_data = it->get<CharacterData>();
    if (auto it = j.find("observed_values"); it != j.end()) a.observed_values = it->get<ObservedValues>();
    if (auto it = j.find("evidence");        it != j.end()) a.evidence = it->get<std::vector<Evidence>>();
}

inline void from_json(const json& j, Implementation& i) {
    i.module = detail::opt<std::string>(j, "module");
    i.rva    = detail::opt<std::uint64_t>(j, "rva");
}

inline void from_json(const json& j, Dispatch& d) {
    d.kind            = detail::get<std::string>(j, "kind", std::string());
    d.table_offset    = detail::opt<int>(j, "table_offset");
    d.slot            = detail::opt<int>(j, "slot");
    d.subtable_module = detail::opt<std::string>(j, "subtable_module");
    d.subtable_rva    = detail::opt<std::uint64_t>(j, "subtable_rva");
    d.resolved        = detail::get<bool>(j, "resolved", false);
}

inline void from_json(const json& j, UserMode& u) {
    if (auto it = j.find("one_to_one_thunk_apis"); it != j.end())
        u.one_to_one_thunk_apis = it->get<std::vector<std::string>>();
    if (auto it = j.find("calling_apis"); it != j.end())
        u.calling_apis = it->get<std::vector<std::string>>();
    u.reachable_from_user_api = detail::get<bool>(j, "reachable_from_user_api", false);
}

inline void from_json(const json& j, Syscall& s) {
    s.ssn         = detail::get<std::uint32_t>(j, "ssn", 0u);
    s.index       = detail::get<int>(j, "index", 0);
    s.name        = detail::get<std::string>(j, "name", std::string());
    s.nargs       = detail::get<int>(j, "nargs", 0);
    s.c_prototype = detail::get<std::string>(j, "c_prototype", std::string());
    if (auto it = j.find("implementation"); it != j.end()) s.implementation = it->get<Implementation>();
    if (auto it = j.find("dispatch");       it != j.end()) s.dispatch = it->get<Dispatch>();
    if (auto it = j.find("user_mode");      it != j.end()) s.user_mode = it->get<UserMode>();
    if (auto it = j.find("args");           it != j.end()) s.args = it->get<std::vector<Argument>>();
}

// ------------------------------------------------------------- database ----

class Database {
public:
    static Database fromFile(const std::string& path) {
        std::ifstream in(path);
        if (!in) throw std::runtime_error("cannot open " + path);
        json j;
        in >> j;
        return fromJson(j);
    }

    static Database fromJson(const json& j) {
        Database db;
        db.schema_version_ = detail::get<std::string>(j, "schema_version", std::string());
        if (db.schema_version_.empty() || db.schema_version_[0] != '2')
            throw std::runtime_error("unsupported schema_version '" + db.schema_version_ +
                                     "' (this reader handles 2.x)");
        db.build_      = j.value("build", json::object());
        db.convention_ = j.value("calling_convention", json::object());
        db.stats_      = j.value("statistics", json::object());
        db.syscalls_   = j.at("syscalls").get<std::vector<Syscall>>();
        for (std::size_t i = 0; i < db.syscalls_.size(); ++i) {
            db.by_name_[db.syscalls_[i].name] = i;
            db.by_ssn_[db.syscalls_[i].ssn]   = i;
        }
        return db;
    }

    const std::vector<Syscall>& syscalls() const { return syscalls_; }
    const json& build()             const { return build_; }
    const json& callingConvention() const { return convention_; }
    const json& statistics()        const { return stats_; }
    const std::string& schemaVersion() const { return schema_version_; }

    const Syscall* byName(const std::string& n) const {
        auto it = by_name_.find(n);
        return it == by_name_.end() ? nullptr : &syscalls_[it->second];
    }
    const Syscall* bySsn(std::uint32_t ssn) const {
        auto it = by_ssn_.find(ssn);
        return it == by_ssn_.end() ? nullptr : &syscalls_[it->second];
    }

    std::pair<std::size_t, std::size_t> getSyscallRange() const{
        std::size_t maxKey = 0;
        std::size_t minKey = -1;

        for (const auto& [_, syscall_id] : by_name_){
            maxKey = std::max(maxKey, syscall_id);
            minKey = std::min(minKey, syscall_id);
        }

        return std::make_pair(minKey, maxKey);
    }

    template <typename Pred>
    std::vector<const Syscall*> where(Pred p) const {
        std::vector<const Syscall*> out;
        for (const auto& s : syscalls_)
            if (p(s)) out.push_back(&s);
        return out;
    }

private:
    std::string          schema_version_;
    json                 build_, convention_, stats_;
    std::vector<Syscall> syscalls_;
    std::unordered_map<std::string, std::size_t>   by_name_;
    std::unordered_map<std::uint32_t, std::size_t> by_ssn_;
};

}  // namespace win32k
