#ifndef debugg_debugger_hpp
#define debugg_debugger_hpp

#include <iomanip>
#include <fcntl.h>
#include <fstream>
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"
#include "breakpoint.hpp"
#include "registers.hpp"

std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> out{};
    std::stringstream ss{s};
    std::string item;

    while (std::getline(ss, item, delimiter))
    {
        out.push_back(item);
    }
    return out;
}

class debugger
{
private:
    std::string prog_name;
    pid_t pid;
    int n = 1;
    uint64_t load_addr;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    void handle_command(const std::string &);
    void execute_continue();
    void handle_sigtrap(siginfo_t);
    void execute_exit();
    void load_address();
    siginfo_t get_signal_info();
    void wait_for_signal();
    bool has_debug_info(const elf::elf &);
    std::map<std::intptr_t, breakpoint> breakpoints;

public:
    debugger(std::string prog_n, pid_t p) : prog_name{std::move(prog_n)}, pid(p)
    {
        auto fd = open(prog_name.c_str(), O_RDONLY);
        m_elf = elf::elf{elf::create_mmap_loader(fd)};
        if (has_debug_info(m_elf))
            m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
        else
            std::cerr << "\x1b[31mWarning: .debug_info section is missing. Continuing without DWARF information.\x1b[0m\n"
                      << std::endl;
    }
    void run();
    void set_breakpoint_at(std::intptr_t);
    void dump_registers();
    void print_source(const std::string &, unsigned line, unsigned n_line_context = 2);
    void step_over_breakpoint();
    void info_breakpoints();
    void delete_breakpoints();
    uint64_t offset_load_address(uint64_t addr) { return addr - load_addr; }
    auto get_function_from_pc(uint64_t pc) -> dwarf::die;
    auto get_line_entry_from_pc(uint64_t pc) -> dwarf::line_table::iterator;
};

void debugger::run()
{
    std::cout << "\x1b[32mDebugging has started with pid: \x1b[0m" << pid << std::endl;
    load_address();
    wait_for_signal();

    char *line = nullptr;
    while ((line = linenoise("\x1b[38;5;228mMYdbg> \x1b[0m")) != nullptr)
    {
        handle_command(line);
        linenoiseHistoryAdd(line);
        // linenoiseHistoryFree();
    }
}

void debugger::execute_continue()
{
    step_over_breakpoint();
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    wait_for_signal();
}

void debugger::load_address()
{
    FILE *pipe = popen(static_cast<std::string>("cat /proc/" + std::to_string(static_cast<uint64_t>(pid)) + "/maps | head -n 1 | grep -o '^[^ -]*'").c_str(), "r");
    char buffer[256];
    fgets(buffer, 256, pipe);
    pclose(pipe);
    load_addr = std::stol(buffer, nullptr, 16);
    std::cout << "\x1b[31mThe starting adress is:\x1b[0m 0x" << std::hex << load_addr << std::endl;
}

void debugger::wait_for_signal()
{
    int wait_status;
    auto options = 0;
    waitpid(pid, &wait_status, options);
    //activate for dwarf -4 only
    auto siginfo =get_signal_info();
    switch(siginfo.si_signo){
        case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
        case SIGSEGV:
        std::cout<<"OOPS :( segfault. Reason: "<<siginfo.si_code<<std::endl;
        break;
        default:
        std::cout<<strsignal(siginfo.si_code)<<std::endl;
    }
}

void debugger::info_breakpoints()
{
    int i = 1;
    for (auto &b_p : breakpoints)
    {
        std::cout << "\x1b[38;5;123mBreakpoint \x1b[38;5;124m" << i << "\x1b[38;5;123m at:\x1b[0m 0x" << b_p.first << std::endl;
        i++;
    }
}

// void debugger::delete_breakpoints(){
//     for(auto &b_p:breakpoints){
//         breakpoints.erase(b_p.first);
//     }
//     step_over_breakpoint();
// }

void debugger::set_breakpoint_at(std::intptr_t address)
{
    breakpoint bp(pid, address);
    if (bp.b_enable())
    {
        std::cout << "\x1b[38;5;118mBreakpoint " << n << " applied at:\x1b[0m 0x" << std::hex << address << std::endl;
        breakpoints[address] = bp;
        n++;
    }
    else
        std::cerr << "\x1b[38;5;160mCannot access memory at\x1b[0m: 0x" << std::hex << address << std::endl;
}

void debugger::dump_registers()
{   
    for (const auto &rd : dump_register_descriptors)
    {
        std::cout << "\x1b[38;5;196m" << std::setw(9) << std::left << rd.name << "\x1b[38;5;123m: 0x" << std::setfill('0') << std::setw(16) << std::right << std::hex << get_register_value(pid, rd.r) << "\x1b[0m" << std::setfill(' ') << std::endl;
    }
}

void debugger::step_over_breakpoint()
{
    auto breakpoint_loc = get_rip(pid) - 1;
    if (breakpoints.count(breakpoint_loc))
    {
        std::cout<<get_rip(pid)<<std::endl;
        auto &bp = breakpoints[breakpoint_loc];
        if (bp.is_b_enable())
        {
            //set_rip(pid, breakpoint_loc);   //for non dwarf activate it
            bp.b_disable();
            ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
            wait_for_signal();
            bp.b_enable();
        }
    }
}

bool debugger::has_debug_info(const elf::elf &file)
{
    for (const auto &section : file.sections())
    {
        if (section.get_name() == ".debug_info")
        {
            return true;
        }
    }
    return false;
}

siginfo_t debugger::get_signal_info()
{
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, pid, nullptr, &info);
    return info;
}

void debugger::handle_sigtrap(siginfo_t info)
{
    switch (info.si_code)
    {
    // one of these will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        set_rip(pid, get_rip(pid) - 1);
        std::cout << "Breakpoint hit at: 0x" << std::hex << get_rip(pid) << std::endl;
        auto offset_pc = offset_load_address(get_rip(pid));
        // std::cout<<get_rip(pid)<<" "<<offset_pc<<std::endl;
        auto line_entry = get_line_entry_from_pc(offset_pc);
        print_source(line_entry->file->path, line_entry->line);
        return;
    }
    // this will be set if the signal was sent by single stepping
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

dwarf::die debugger::get_function_from_pc(uint64_t pc)
{
    for (auto &cu : m_dwarf.compilation_units())
    {
        if (die_pc_range(cu.root()).contains(pc))
        {
            for (const auto &die : cu.root())
            {
                if (die.tag == dwarf::DW_TAG::subprogram)
                {
                    if (die_pc_range(die).contains(pc))
                    {
                        return die;
                    }
                }
            }
        }
    }

    throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc)
{
    for (auto &cu : m_dwarf.compilation_units())
    {
        auto range = die_pc_range(cu.root());
        if (range.contains(pc)) // current issue
        {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end())
            {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else
            {
                return it;
            }
        }
    }

    std::cerr << "PC: " << std::hex << pc << std::dec << " not in range: " << std::endl;
    throw std::out_of_range{"Cannot find line entry"};
}

void debugger::print_source(const std::string &file_name, unsigned line, unsigned n_lines_context)
{
    std::ifstream file{file_name};

    // Work out a window around the desired line
    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    // Skip lines up until start_line
    while (current_line != start_line && file.get(c))
    {
        if (c == '\n')
        {
            ++current_line;
        }
    }

    // Output cursor if we're at the current line
    std::cout << (current_line == line ? "> " : "  ");

    // Write lines up until end_line
    while (current_line <= end_line && file.get(c))
    {
        std::cout << c;
        if (c == '\n')
        {
            ++current_line;
            // Output cursor if we're at the current line
            std::cout << (current_line == line ? "> " : "  ");
        }
    }

    // Write newline and make sure that the stream is flushed properly
    std::cout << std::endl;
}

void debugger::execute_exit()
{
    kill(pid, SIGKILL);
    exit(0);
}

#endif