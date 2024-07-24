#ifndef debugg_registers_hpp
#define debugg_registers_hpp

#include <vector>

enum class reg
{
    rax,
    rbx,
    rcx,
    rdx,
    rdi,
    rsi,
    rbp,
    rsp,
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,
    rip,
    rflags,
    cs,
    orig_rax,
    fs_base,
    gs_base,
    fs,
    gs,
    ss,
    ds,
    es
};

constexpr std::size_t n_registers = 27;

struct reg_descriptor
{
    reg r;
    int dwarf_r;
    std::string name;
};

static const std::array<reg_descriptor, n_registers> dump_register_descriptors{{
    {reg::rax, 0, "rax"},
    {reg::rbx, 3, "rbx"},
    {reg::rcx, 2, "rcx"},
    {reg::rdx, 1, "rdx"},
    {reg::rdi, 5, "rdi"},
    {reg::rsi, 4, "rsi"},
    {reg::rbp, 6, "rbp"},
    {reg::rsp, 7, "rsp"},
    {reg::rip, -1, "rip"},
    {reg::r8, 8, "r8"},
    {reg::r9, 9, "r9"},
    {reg::r10, 10, "r10"},
    {reg::r11, 11, "r11"},
    {reg::r12, 12, "r12"},
    {reg::r13, 13, "r13"},
    {reg::r14, 14, "r14"},
    {reg::r15, 15, "r15"},
    {reg::orig_rax, -1, "orig_rax"},
    {reg::rflags, 49, "eflags"},
    {reg::fs_base, 58, "fs_base"},
    {reg::gs_base, 59, "gs_base"},
    {reg::cs, 51, "cs"},
    {reg::ds, 53, "ds"},
    {reg::es, 50, "es"},
    {reg::fs, 54, "fs"},
    {reg::gs, 55, "gs"},
    {reg::ss, 52, "ss"},
}};

static const std::array<reg_descriptor, n_registers> g_register_descriptors{{
    {reg::r15, 15, "r15"},
    {reg::r14, 14, "r14"},
    {reg::r13, 13, "r13"},
    {reg::r12, 12, "r12"},
    {reg::rbp, 6, "rbp"},
    {reg::rbx, 3, "rbx"},
    {reg::r11, 11, "r11"},
    {reg::r10, 10, "r10"},
    {reg::r9, 9, "r9"},
    {reg::r8, 8, "r8"},
    {reg::rax, 0, "rax"},
    {reg::rcx, 2, "rcx"},
    {reg::rdx, 1, "rdx"},
    {reg::rsi, 4, "rsi"},
    {reg::rdi, 5, "rdi"},
    {reg::orig_rax, -1, "orig_rax"},
    {reg::rip, -1, "rip"},
    {reg::cs, 51, "cs"},
    {reg::rflags, 49, "eflags"},
    {reg::rsp, 7, "rsp"},
    {reg::ss, 52, "ss"},
    {reg::fs_base, 58, "fs_base"},
    {reg::gs_base, 59, "gs_base"},
    {reg::ds, 53, "ds"},
    {reg::es, 50, "es"},
    {reg::fs, 54, "fs"},
    {reg::gs, 55, "gs"},
}};

uint64_t get_register_value(pid_t pid, reg r)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    auto offset = std::__find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto &&rd)
                                 { return rd->r == r; });
    return *(reinterpret_cast<uint64_t *>(&regs) + (offset - begin(g_register_descriptors)));
}

void set_register_value(pid_t pid, reg r, uint64_t value)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    auto offset = std::__find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto &&rd)
                                 { return rd->r == r; });
    *(reinterpret_cast<uint64_t *>(&regs) + (offset - begin(g_register_descriptors))) = value;
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

uint64_t get_register_value_from_dwarf_regiaters(pid_t pid, unsigned reg_num)
{
    auto reg_pointer = std::__find_if(begin(g_register_descriptors), end(g_register_descriptors), [reg_num](auto &&rd)
                                      { return rd->dwarf_r == reg_num; });
    if (reg_pointer == end(g_register_descriptors))
        throw std::out_of_range("unknown dwarf register");
    return get_register_value(pid, reg_pointer->r);
}

std::string get_register_name(reg r)
{
    auto reg_pointer = std::__find_if(begin(g_register_descriptors), end(g_register_descriptors),
                                      [r](auto &&rd)
                                      { return rd->r == r; });
    return reg_pointer->name;
}

reg get_register_from_name(std::string name)
{
    auto reg_pointer = std::__find_if(begin(g_register_descriptors), end(g_register_descriptors), [name](auto &&rd)
                                      { return rd->name == name; });
    if (reg_pointer == end(g_register_descriptors))
        throw std::out_of_range("unknown register");
    return reg_pointer->r;
}

uint64_t get_rip(pid_t pid)
{
    reg r = reg::rip;
    return get_register_value(pid, r);
}

void set_rip(pid_t pid, uint64_t value)
{
    reg r = reg::rip;
    return set_register_value(pid, r, value);
}

#endif
