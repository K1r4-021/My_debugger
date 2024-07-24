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

enum class symbol_type
{
    notype,  // No type (e.g., absolute symbol)
    object,  // Data object
    func,    // Function entry point
    section, // Symbol is associated with a section
    file,    // Source file associated with the
}; // object file

std::string to_string(symbol_type st)
{
    switch (st)
    {
    case symbol_type::notype:
        return "notype";
    case symbol_type::object:
        return "object";
    case symbol_type::func:
        return "func";
    case symbol_type::section:
        return "section";
    case symbol_type::file:
        return "file";
    }
    return NULL;
}

struct symbol
{
    symbol_type type;
    std::string name;
    std::uintptr_t addr;
};

symbol_type to_symbol_type(elf::stt sym)
{
    switch (sym)
    {
    case elf::stt::notype:
        return symbol_type::notype;
    case elf::stt::object:
        return symbol_type::object;
    case elf::stt::func:
        return symbol_type::func;
    case elf::stt::section:
        return symbol_type::section;
    case elf::stt::file:
        return symbol_type::file;
    default:
        return symbol_type::notype;
    }
};

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
    void single_step_instruction();
    void single_step_instruction_over_breakpoint_check();
    void load_address();
    siginfo_t get_signal_info();
    void wait_for_signal();
    bool has_debug_info(const elf::elf &);
    std::unordered_map<std::intptr_t, breakpoint> breakpoints;

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
    void read_variable();
    void backtrace();
    void set_breakpoint_at(std::intptr_t);
    void set_breakpoint_at_address(std::intptr_t);
    void set_breakpoint_at_function(const std::string &);
    void set_breakpoint_at_source_line(const std::string &, unsigned);
    void dump_registers();
    void print_source(const std::string &, unsigned line, unsigned n_line_context = 2);
    void step_over_breakpoint();
    void info_breakpoints();
    void step_out();
    void step_in();
    void step_over();
    std::vector<symbol> lookup_symbol(const std::string &);
    void delete_breakpoint(std::intptr_t);
    uint64_t offset_load_address(uint64_t addr) { return addr - load_addr; }
    uint64_t offset_dwarf_address(uint64_t addr) { return addr + load_addr; }
    auto get_function_from_pc(uint64_t pc) -> dwarf::die;
    auto get_line_entry_from_pc(uint64_t pc) -> dwarf::line_table::iterator;
    auto read_memory(uint64_t address) -> uint64_t;
    void write_memory(uint64_t address, uint64_t value);
};

class ptrace_expr_context : public dwarf::expr_context
{
private:
    pid_t pid;
    uint64_t load_address;

public:
    ptrace_expr_context(pid_t m_pid,uint64_t m_load_address) : pid(m_pid),load_address(m_load_address) {}

    dwarf::taddr reg(unsigned regnum) override
    {
        return get_register_value_from_dwarf_regiaters(pid, regnum);
    }
    // dwarf::taddr pc() override{
    //     struct user_regs_struct regs;
    //     ptrace(PTRACE_GETREGS,pid,nullptr,&regs);
    //     return regs.rip-load_address;
    // }
    dwarf::taddr deref_size(dwarf::taddr address, unsigned size) override
    {
        // TODO take into account size
        return ptrace(PTRACE_PEEKDATA, pid, address, nullptr);
    }
};

template class std::initializer_list<dwarf::taddr>;

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

uint64_t debugger::read_memory(uint64_t address)
{
    return ptrace(PTRACE_PEEKDATA, pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value)
{
    ptrace(PTRACE_POKEDATA, pid, address, value);
}

void debugger::backtrace()
{
    auto output_frame = [frame_number = 0](auto &&func) mutable
    {
        std::cout << "frame #" <<frame_number++ << ":\x1b[38;5;33m 0x" << dwarf::at_low_pc(func) << " \x1b[0m" << dwarf::at_name(func) << std::endl;
    };
    auto current_func = get_function_from_pc(offset_load_address(get_rip(pid)));
    output_frame(current_func);
    auto frame_pointer = get_register_value(pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);
    while (dwarf::at_name(current_func) != "main")
    {
        current_func = get_function_from_pc(offset_load_address(return_address));
        output_frame(current_func);
        frame_pointer = read_memory(frame_pointer);
        return_address = read_memory(frame_pointer + 8);
    }
}

void debugger::single_step_instruction()
{
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::single_step_instruction_over_breakpoint_check()
{
    if (breakpoints.count(get_rip(pid)))
        step_over_breakpoint();
    else
        single_step_instruction();
}

void debugger::step_out()
{
    auto return_address = read_memory(get_register_value(pid, reg::rbp) + 8);
    bool should_remove_breakpoint = false;
    if (!breakpoints.count(return_address))
    {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }
    execute_continue();
    if (should_remove_breakpoint)
        delete_breakpoint(return_address);
}

void debugger::step_in()
{
    auto line = get_line_entry_from_pc(offset_load_address(get_rip(pid)))->line;

    while (get_line_entry_from_pc(offset_load_address(get_rip(pid)))->line == line)
    {
        single_step_instruction_over_breakpoint_check();
    }

    auto line_entry = get_line_entry_from_pc(offset_load_address(get_rip(pid)));
    print_source(line_entry->file->path, line_entry->line);
}

void debugger::step_over()
{
    auto func = get_function_from_pc(offset_load_address(get_rip(pid)));
    auto func_entry = at_low_pc(func);
    auto func_end = at_high_pc(func);
    auto line = get_line_entry_from_pc(func_entry);
    auto start_line = get_line_entry_from_pc(offset_load_address(get_rip(pid)));

    std::vector<std::intptr_t> to_delete{};

    while (line->address < func_end)
    {
        auto load_address = offset_dwarf_address(line->address);
        if (line->address != start_line->address && !breakpoints.count(load_address))
        {
            set_breakpoint_at_address(load_address);
            to_delete.push_back(load_address);
        }
        ++line;
    }
    auto return_address = read_memory(get_register_value(pid, reg::rbp) + 8);
    if (!breakpoints.count(return_address))
    {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    execute_continue();

    for (auto addr : to_delete)
    {
        delete_breakpoint(addr);
    }
}

void debugger::read_variable()
{
    auto func = get_function_from_pc(offset_load_address(get_rip(pid)));
    for (const auto &die : func)
    {
        if (die.tag == dwarf::DW_TAG::variable)
        {
            auto val_loc = die[dwarf::DW_AT::location];
            if (val_loc.get_type() == dwarf::value::type::exprloc)
            {
                ptrace_expr_context context(pid,load_addr);
                auto result = val_loc.as_exprloc().evaluate(&context);
                switch (result.location_type)
                {
                case dwarf::expr_result::type::address:
                {
                    auto value = read_memory(result.value);
                    std::cout << dwarf::at_name(die) << " (0x" << std::hex << result.value << ") = " << value << std::endl;
                }
                case dwarf::expr_result::type::reg:
                {
                    auto value = get_register_value_from_dwarf_regiaters(pid, result.value);
                    std::cout << dwarf::at_name(die) << " (ref " << result.value << ") = " << value << std::endl;
                    break;
                }
                default:
                    throw std::runtime_error("Unhandled variable location");
                }
            }
        }
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
    // activate for dwarf -4 only
    auto siginfo = get_signal_info();
    switch (siginfo.si_signo)
    {
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cout << "OOPS :( segfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << strsignal(siginfo.si_code) << std::endl;
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

void debugger::delete_breakpoint(std::intptr_t bp_addr)
{
    if (breakpoints.at(bp_addr).is_b_enable())
    {
        breakpoints.at(bp_addr).b_disable();
    }
    breakpoints.erase(bp_addr);
}

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

void debugger::set_breakpoint_at_address(std::intptr_t address)
{
    breakpoint bp(pid, address);
    if (bp.b_enable())
        breakpoints[address] = bp;
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
    if (breakpoints.count(get_rip(pid)))
    {
        auto &bp = breakpoints[get_rip(pid)];
        if (bp.is_b_enable())
        {
            // set_rip(pid, get_rip(pid)-1);   //for non dwarf activate it
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
        if (get_rip(pid) < load_addr)
            uint64_t offset_pc = get_rip(pid);
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

void debugger::set_breakpoint_at_function(const std::string &name)
{
    for (const auto &cu : m_dwarf.compilation_units())
    {
        for (const auto &die : cu.root())
        {
            if (die.has(dwarf::DW_AT::name) && at_name(die) == name)
            {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry; // skip prologue
                set_breakpoint_at(offset_dwarf_address(entry->address));
            }
            else if (!die.has(dwarf::DW_AT::name))
                std::cerr << "\x1b[31mInvalid argument\x1b[0m" << std::endl;
        }
    }
}

void debugger::set_breakpoint_at_source_line(const std::string &file, unsigned line)
{
    for (const auto &cu : m_dwarf.compilation_units())
    {
        if (file.find(at_name(cu.root())) == 0)
        {
            const auto &lt = cu.get_line_table();

            for (const auto &entry : lt)
            {
                if (entry.is_stmt && entry.line == line)
                {
                    set_breakpoint_at(offset_dwarf_address(entry.address));
                    return;
                }
            }
        }
    }
}

std::vector<symbol> debugger::lookup_symbol(const std::string &name)
{
    std::vector<symbol> syms;
    for (auto &sec : m_elf.sections())
    {
        if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
            continue;

        for (auto sym : sec.as_symtab())
        {
            if (sym.get_name() == name)
            {
                auto &d = sym.get_data();
                syms.push_back(symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
            }
            else if (name == "all")
            {
                auto &d = sym.get_data();
                syms.push_back(symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
            }
        }
    }

    return syms;
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
