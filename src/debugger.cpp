#include <sys/wait.h>
#include <algorithm>
#include <sys/user.h>
#include <sys/personality.h>
#include "linenoise.h"
#include "debugger.hpp"

void debugger::handle_command(const std::string &line)
{
    auto args = split(line, ' ');
    auto command = args[0];
    if (command == "continue" || command == "c" || command == "cont")
        execute_continue();
    else if (command == "stepi")
    {
        single_step_instruction_over_breakpoint_check();
        auto offset_pc = offset_load_address(get_rip(pid));
        if (get_rip(pid) < load_addr)
            uint64_t offset_pc = get_rip(pid);
        auto line_entry = get_line_entry_from_pc(offset_pc);
        print_source(line_entry->file->path, line_entry->line);
    }
    else if (command == "step")
    {
        if (args[1] == "into")
            step_in();
        if (args[1] == "out")
            step_out();
        if (args[1] == "over")
            step_over();
    }
    else if (command == "ni")
        step_over();
    else if (command == "si")
        step_in();
    else if (command == "finish")
        step_out();
    else if (command == "exit" || command == "exit()" || command == "q")
        execute_exit();
    else if (command == "bp" || command == "breakpoint")
    {
        if (args[1].find("0x") == 0)
        {
            std::string addr{args[1], 2};
            if (!breakpoints.count(std::stol(addr, nullptr, 16)))
                set_breakpoint_at(std::stol(addr, nullptr, 16));
            else
                std::cout << "\x1b[38;5;165mBreakpoint already applied at\x1b[0m: 0x" << std::stol(addr, nullptr, 16) << std::endl;
        }
        else if (std::all_of(args[1].begin(), args[1].end(), ::isdigit))
        {
            std::string addr{args[1]};
            if (!breakpoints.count(std::stol(addr)))
                set_breakpoint_at(std::stol(addr));
            else
                std::cout << "\x1b[38;5;165mBreakpoint already applied at\x1b[0m: 0x" << std::stol(addr) << std::endl;
        }
        else if (args[1].find("base") == 0)
        {
            std::string addr{args[1], args[1].find("+") + 1};
            if (addr.find("0x") == 0)
            {
                std::string addr1{addr, 2};
                if (!breakpoints.count(std::stol(addr1, nullptr, 16) + load_addr))
                    set_breakpoint_at(std::stol(addr1, nullptr, 16) + load_addr);
                else
                    std::cout << "\x1b[38;5;165mBreakpoint already applied at\x1b[0m: 0x" << std::stol(addr1, nullptr, 16) + load_addr << std::endl;
            }
            else if (std::all_of(addr.begin(), addr.end(), ::isdigit))
            {
                if (!breakpoints.count(std::stol(addr) + load_addr))
                    set_breakpoint_at(std::stol(addr) + load_addr);
                else
                    std::cout << "\x1b[38;5;165mBreakpoint already applied at\x1b[0m: 0x" << std::stol(addr) + load_addr << std::endl;
            }
            else
            {
                std::cerr << "\x1b[31mInvalid argument\x1b[0m" << std::endl;
            }
        }
        else if (args[1].find(':') != std::string::npos)
        {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stol(file_and_line[1]));
        }
        else
        {
            set_breakpoint_at_function(args[1]);
        }
    }
    else if (command == "dump")
    {
        dump_registers();
    }
    else if (command == "info")
    {
        if (args[1] == "breakpoint" || args[1] == "bp")
            info_breakpoints();
        else if(args[1]=="variable")
            read_variable();
    }
    else if (command == "delete")
    {
        if (args[1] == "breakpoints" || args[1] == "bp")
        {
            std::vector<std::intptr_t> to_delete;
            for (const auto &bp : breakpoints)
            {
                to_delete.push_back(bp.first);
            }
            for (const auto &key : to_delete)
            {
                delete_breakpoint(key);
            }
            to_delete.clear();
            n = 1;
            std::cout << "\x1b[38;5;76mBreakpoints deleted\x1b[0m" << std::endl;
        }
        else
            std::cerr << "\x1b[35mUnknown Command.\x1b[0m";
    }
    else if (command == "print")
    {
        std::string regi{args[1]};
        std::cout << "\x1b[38;5;196m" << args[1] << "\x1b[0m = \x1b[38;5;123m" << std::dec << get_register_value(pid, get_register_from_name(regi)) << "\x1b[0m" << "\t0x" << std::hex << get_register_value(pid, get_register_from_name(regi)) << std::endl;
    }
    else if (command == "set")
    {
        std::string val{args[2], 2};
        set_register_value(pid, get_register_from_name(args[1]), std::stol(val, 0, 16));
    }
    else if (command == "symbol")
    {
        auto syms = lookup_symbol(args[1]);
        for (auto &&s : syms)
            std::cout << "\x1b[38;5;76m" << s.name << "\x1b[38;5;75m " << to_string(s.type) << "\x1b[38;5;160m 0x" << std::hex << s.addr << std::dec << "\x1b[0m" << std::endl;
    }
    else if (command == "backtrace")
    {
        backtrace();
    }
    else if (command == "help")
    {
        std::cout << "\x1b[38;5;160mDebugger Commands:\n"
                  << "\x1b[38;5;27m  continue, c, cont                  \x1b[0m- Continue execution until the next breakpoint\n"
                  << "\x1b[38;5;27m  stepi                              \x1b[0m- Single step instruction\n"
                  << "\x1b[38;5;27m  si, step into                      \x1b[0m- Step into the next instruction\n"
                  << "\x1b[38;5;27m  ni, step over                      \x1b[0m- Step over the next instruction\n"
                  << "\x1b[38;5;27m  finish, step out                   \x1b[0m- Step out the next instruction\n"
                  << "\x1b[38;5;27m  exit, exit(), q                    \x1b[0m- Exit the debugger\n"
                  << "\x1b[38;5;27m  bp, breakpoint <addr>              \x1b[0m- Set a breakpoint at the specified address\n"
                  << "    \x1b[0m- Address can be in hex (0x...) or decimal\n"
                  << "    \x1b[0m- Address can be base+offset (e.g., base+0x100)\n"
                  << "\x1b[38;5;27m  bp, breakpoint <line>:<filename>   \x1b[0m- Set a breakpoint at the specified line number\n"
                  << "\x1b[38;5;27m  bp, breakpoint <function name>     \x1b[0m- Set a breakpoint at the specified function\n"
                  << "\x1b[38;5;27m  dump                               \x1b[0m- Dump the current state of the registers\n"
                  << "\x1b[38;5;27m  info breakpoint/bp                 \x1b[0m- Show information about breakpoints\n"
                  << "\x1b[38;5;27m  delete breakpoints/bp              \x1b[0m- Delete all the breakpoints\n"
                  << "\x1b[38;5;27m  print <register>                   \x1b[0m- Print the value of the specified register\n"
                  << "\x1b[38;5;27m  set <register> <value>             \x1b[0m- Set the specified register to the given value\n"
                  << "    \x1b[0m- Value must be in hex (0x...)\n"
                  << "\x1b[38;5;27m  symbol <function>                  \x1b[0m-Print the symbol of function\n"
                  << "    - if \"all\" is used instead of function name \x1b[0mit prints symbol of all sections\n"
                  << "\x1b[38;5;27m  backtrace                          \x1b[0m-which gives you the chain of function calls\n"
                  << "\x1b[38;5;27m  help                               \x1b[0m- Show this help menu\n";
    }
    else
        std::cerr << "\x1b[35mUnknown Command. Type \"help\" for help\x1b[0m\n";
}

void execute_debugee(const std::string &prog_name)
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
    {
        std::cerr << "\x1b[31mPtrace unsuccessfull\x1b[0m\n";
        return;
    }
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

void program_check(std::string program_name)
{
    if ((fopen(program_name.c_str(), "r")) == NULL)
    {
        std::cerr << "\x1b[31mSource specified not found\x1b[0m\n";
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **arg)
{
    if (argc < 2)
    {
        std::cerr << "\x1b[1;31mProgram to be debugged is not specified\n\x1b[35mUsage: ./debugger <program>\x1b[0m";
        return EXIT_FAILURE;
    }
    std::string prog = arg[1];
    program_check(prog);
    pid_t pid = fork();
    if (pid == 0)
    {
        // child process
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(prog);
    }
    else if (pid >= 1)
    {
        // parent process
        debugger dbg{prog, pid};
        dbg.run();
    }
    else
    {
        std::cerr << "\x1B[1;31mERROR in creating process\x1b[0m :(" << std::endl;
    }
}
