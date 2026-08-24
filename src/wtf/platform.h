// Axel '0vercl0k' Souchet - April 27 2020
#pragma once

#if defined(__i386__) || defined(_M_IX86)
#define ARCH_X86
#elif defined(__amd64__) || defined(_M_X64)
#define ARCH_X64
#elif defined(__aarch64__) || defined(_M_ARM64)
#define ARCH_ARM64
#else
#error Platform not supported.
#endif

#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#define SYSTEM_PLATFORM "Windows"

#include <windows.h>
using ssize_t = SSIZE_T;
#define __builtin_bswap16 _byteswap_ushort
#define __builtin_bswap32 _byteswap_ulong
#define __builtin_bswap64 _byteswap_uint64
#if defined ARCH_X86
#define WINDOWS_X86
#elif defined ARCH_X64
#define WINDOWS_X64
#elif defined ARCH_ARM64
#define WINDOWS_ARM64
#endif
#elif defined(linux) || defined(__linux) || defined(__FreeBSD__) ||            \
    defined(__FreeBSD_kernel__) || defined(__MACH__)
#define POSIX

#if defined(__MACH__)
#define SYSTEM_PLATFORM "macOS"
#elif defined(linux) || defined(__linux)
#define SYSTEM_PLATFORM "Linux"
// HAS_KVM is only defined on x86_64 because the KVM backend uses
// x86-specific KVM structures (kvm_lapic_state, kvm_regs, kvm_sregs,
// etc.) that do not exist in the arm64 KVM ABI. Porting the KVM
// backend to arm64 would require a separate implementation using
// the arm64 KVM one_reg interface.
#if defined(ARCH_X64)
#define HAS_KVM
#endif
#else
#error An error occured
#endif

#include <cstdlib>
#include <sys/mman.h>
#include <unistd.h>

#if defined(ARCH_ARM64)
#if defined(__clang__)
#define __debugbreak() __builtin_debugtrap()
#else
#include <signal.h>
#define __debugbreak() raise(SIGTRAP)
#endif
#else
#define __debugbreak() __asm__("int $3")
#endif
#define ExitProcess(x) exit(x)
#define aligned_free(x) free(x)

#if defined(__MACH__)
#if defined ARCH_X86
#define OSX_X86
#elif defined ARCH_X64
#define OSX_X64
#elif defined ARCH_ARM64
#define OSX_ARM64
#endif
#else
#if defined ARCH_X86
#define LINUX_X86
#elif defined ARCH_X64
#define LINUX_X64
#elif defined ARCH_ARM64
#define LINUX_ARM64
#endif
#endif

#else
#error Platform not supported.
#endif