// 1ndahous3 - March 4 2023
#include "backend.h"
#include "targets.h"
#include "crash_detection_umode.h"
#include "utils.h"

#include "win32k_mutate.h"
#include "win32k_write.h"

#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <deque>
#include <iostream>
#include <vector>
#include <optional>
#include <unordered_map>
#include <functional>


/* Syscall Handling:
    - If arrays it's better to start with the largest input possible (so that the mutator can shrink its size)
*/
namespace Syscall {

using namespace helpers;
using namespace win32k::value;
using namespace win32k::target;

std::deque<CallFrame> syscallToModify{};
win32k::Database SyscallDatabase = win32k::Database::fromFile("win32k_syscalls_26100.json");


bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {
    std::vector<CallFrame> Root = Deserialize(Buffer, BufferSize);
    
    for (const auto& f : Root){
        std::cout << "Frame with name " << f.name() << "\n";
        syscallToModify.push_front(f);
    }
        
    return true;
}


void insertSyscall(std::string syscallName, Backend_t* Backend){
    if (syscallToModify.size() == 0) {
        //
        // We are done with the testcase so return to the engine.
        //
        return g_Backend->Stop(Ok_t());
    }

    //
    // Let's insert the testcase in memory now.
    //
    auto &Testcase = syscallToModify.front();
    FrameView fw = FrameView::bind(Testcase, SyscallDatabase);
            
    if (Testcase.name() != syscallName){
        //
        // If some syscalls are inserted between the expected ones\
        //
        DebugPrint("Captured {} instead of {}\n", Testcase.name(), syscallName);
        return;
    }

    DebugPrint("Going to insert testcase");

    InPlaceWriter writer{ *Backend };
    PlacedCall c = writer.WriteFrame(fw);

    if (!c.ok) {
        DebugPrint("Failed to place the call\n");
        return;
    }

    //
    // We're done with this testcase!
    //
    syscallToModify.pop_front();

    Backend->PrintRegisters();
}


bool Init(const Options_t &Opts, const CpuState_t &) {
    DebugPrint("Fuzzing {}", Opts.TargetName);

    std::vector<std::string> syscallsToParse{};
    const Gva_t Rip = Gva_t(g_Backend->Rip());

    if (!g_Backend->SetBreakpoint(Rip, [](Backend_t *Backend) {
        DebugPrint(
            "This is a breakpoint executed before the first instruction :)\n");
    })) {
        DebugPrint("Failed to SetBreakpoint on first instruction\n");
        return false;
    } 

    for (const auto& syscallName : syscallsToParse){
        std::string breakName = Opts.TargetName + "!" + syscallName;
        if (!g_Backend->SetBreakpoint(breakName.c_str(), std::bind(insertSyscall, syscallName, std::placeholders::_1))) {
            DebugPrint("Failed to SetBreakpoint ProcessPacket\n");
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