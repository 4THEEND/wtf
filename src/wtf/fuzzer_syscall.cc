// 1ndahous3 - March 4 2023
#include "backend.h"
#include "targets.h"
#include "crash_detection_umode.h"
#include "utils.h"

#include "win32k_mutate.h"
#include "win32k_write.h"
#include "win32k_capture.h"

#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <deque>
#include <iostream>
#include <vector>
#include <optional>
#include <unordered_map>
#include <functional>
#include <unordered_set>


/* Syscall Handling:
    - If arrays it's better to start with the largest input possible (so that the mutator can shrink its size)
*/
namespace Syscall {

using namespace helpers;
using namespace win32k::value;
using namespace win32k::target;
using namespace win32k::access;

std::deque<CallFrame> syscallToModify{};
win32k::Database SyscallDatabase = win32k::Database::fromFile("win32k_syscalls_26100.json");


inline Registers_t toWtf(Reg r) {
    switch (r) {
        case Reg::Rax: return Registers_t::Rax;
        case Reg::Rcx: return Registers_t::Rcx;
        case Reg::Rdx: return Registers_t::Rdx;
        case Reg::Rsp: return Registers_t::Rsp;
        case Reg::R8:  return Registers_t::R8;
        case Reg::R9:  return Registers_t::R9;
        case Reg::R10: return Registers_t::R10;
    }
}


void readParameters(Backend_t* Backend, std::string syscallName){
    Access access{};
    access.read_mem = [&](uint64_t g, void* d, size_t n) { return Backend->VirtRead(Gva_t(g), (uint8_t*)d, n); };
    access.read_reg  = [&](Reg r) { return Backend->GetReg(toWtf(r)); };

    win32k::capture::FrameCapturer cap{ access };
    win32k::capture::CaptureResult res{};

    auto frame = cap.Capture(*SyscallDatabase.byName(syscallName), &res);
    if (!res.ok) {
        std::cout << "Pbm while reading the dump\n";
        return;
    }

    std::cout << win32k::value::toJson(frame.value()) << "\n";
}


bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {
    std::vector<CallFrame> Root = Deserialize(Buffer, BufferSize);

    for (const auto& f : Root){
        DebugPrint("Frame with name {} \n", f.name());
        syscallToModify.push_front(f);
    }
        
    return true;
}


void insertSyscall(std::string syscallName, Backend_t* Backend){
    
    //
    // The first time we hit this breakpoint, we
    // grab the return address and we set a
    // breakpoint there to finish the testcase.
    //
    static std::unordered_set<std::string> setReturnBreakpoints{};

    if (setReturnBreakpoints.find(syscallName) == setReturnBreakpoints.end()) {
        setReturnBreakpoints.insert(syscallName);
        const auto ReturnAddress = Backend->VirtReadGva(Gva_t(Backend->Rsp()));

        if (!Backend->SetBreakpoint(ReturnAddress, 
            [](Backend_t *Backend) {
                DebugPrint("Hit return breakpoint!\n");
                if (syscallToModify.size() == 0) {
                    return g_Backend->Stop(Ok_t());
                }
            })) {

            fmt::print("Failed to set breakpoint on return\n");
            std::abort();
        }
    }

    auto &Testcase = syscallToModify.front();
    FrameView fw = FrameView::bind(Testcase, SyscallDatabase);
            
    if (Testcase.name() != syscallName){
        //
        // If some syscalls are inserted between the expected ones
        //
        DebugPrint("Captured {} instead of {}\n", Testcase.name(), syscallName);
        return;
    }


    //
    // Let's insert the testcase in memory now.
    //
    DebugPrint("Going to insert testcase\n");
    
    InPlaceWriter writer{ *Backend };
    PlacedCall c = writer.WriteFrame(fw);

    if (!c.ok) {
        DebugPrint("Failed to place the call\n");
        std::abort();
    }
    DebugPrint("Call placed\n");

    //
    // We're done with this testcase!
    //
    syscallToModify.pop_front();
}


bool Init(const Options_t &Opts, const CpuState_t &) {
    DebugPrint("Fuzzing {}\n", Opts.TargetName);

    // TODO: Resolve that using corpus
    std::vector<std::string> syscallsToParse{ "NtDeviceIoControlFile" };

    //
    // Catch context-switches.
    //
    if (!g_Backend->SetBreakpoint("nt!SwapContext", [](Backend_t *Backend) {
        DebugPrint("nt!SwapContext\n");
        Backend->Stop(Cr3Change_t());
      })) {
        fmt::print("Failed to SetBreakpoint SwapContext\n");
        return false;
    }

    //
    // NOP the calls to DbgPrintEx. WHYYYYYYYYYYYYYY ??????
    //
    if (!g_Backend->SetBreakpoint("nt!DbgPrintEx", [](Backend_t *Backend) {
        const Gva_t FormatPtr = Backend->GetArgGva(2);
        const std::string &Format = Backend->VirtReadString(FormatPtr);
        DebugPrint("DbgPrintEx: {}", Format);
        Backend->SimulateReturnFromFunction(0);
      })) {
        fmt::print("Failed to SetBreakpoint DbgPrintEx\n");
        return false;
    }

    //
    // Catch bugchecks.
    //
    if (!g_Backend->SetBreakpoint("nt!KeBugCheck2", [](Backend_t *Backend) {
        const uint32_t BCode = Backend->GetArg4(0);
        const uint64_t B0 = Backend->GetArg8(1);
        const uint64_t B1 = Backend->GetArg8(2);
        const uint64_t B2 = Backend->GetArg8(3);
        const uint64_t B3 = Backend->GetArg8(4);
        const uint64_t B4 = Backend->GetArg8(5);
        const std::string Filename =
            fmt::format("crash-{:#x}-{:#x}-{:#x}-{:#x}-{:#x}-{:#x}", BCode, B0,
                        B1, B2, B3, B4);
        DebugPrint("KeBugCheck2: {}\n", Filename);
        Backend->Stop(Crash_t(Filename));
      })) {
        fmt::print("Failed to SetBreakpoint KeBugCheck2\n");
        return false;
    }


    for (const auto& syscallName : syscallsToParse){
        std::string breakName = "nt!" + syscallName;
        if (!g_Backend->SetBreakpoint(breakName.c_str(), std::bind(insertSyscall, syscallName, std::placeholders::_1))) {
            DebugPrint("Failed to SetBreakpoint {}\n", breakName);
            return false;
        }
    }

    return true;
}


bool Restore() { return true; }

//
// Register the target.
//
Target_t Syscall("syscall", Init, InsertTestcase, Restore, win32k::mutate::CustomMutator_t::Create);

} // namespace Syscall