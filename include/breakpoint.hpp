#ifndef debugg_breakpoint_hpp
#define debugg_breakpoint_hpp

#include <sys/ptrace.h>
#include <unistd.h>
#include <string>
#include <iostream>

class breakpoint
{
    pid_t pid;
    bool enabled;
    std::intptr_t b_address;
    uint8_t b_data;

public:
    breakpoint() = default;
    breakpoint(pid_t d_pid, std::intptr_t addr) : pid(d_pid), b_address(addr), b_data(), enabled(false) {};
    int b_enable();
    void b_disable();
    bool is_b_enable() const { return enabled; }
    intptr_t get_adress() const { return b_address; }
};

int breakpoint::b_enable()
{
    auto data = ptrace(PTRACE_PEEKDATA, pid, b_address, nullptr);
    b_data = static_cast<uint8_t>(data & 0xff);
    uint64_t int3 = 0xcc;
    uint64_t b_int3 = ((data & ~0xff) | int3);
    enabled = true;
    if (ptrace(PTRACE_POKEDATA, pid, b_address, b_int3) >= 0)
        return 1;
    return 0;
}

void breakpoint::b_disable()
{
    auto data = ptrace(PTRACE_PEEKDATA, pid, b_address, nullptr);
    auto previous_data = ((data & ~0xff) | b_data);
    ptrace(PTRACE_POKEDATA, pid, b_address, previous_data);
    enabled = false;
}

#endif
