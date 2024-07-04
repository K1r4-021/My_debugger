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
    // else if (command == "si" || command == "stepinto")
    //     ptrace(PTRACE_SINGLESTEP, pid);
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
        else
        {
            std::cerr << "\x1b[31mInvalid argument\x1b[0m" << std::endl;
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
    }
    // else if (command=="delete")
    // {
    //     if(args[1]=="breakpoints")
    //         delete_breakpoints();
    // }
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
    else if (command == "help")
    {
        std::cout << "Debugger Commands:\n"
                  << "  continue, c, cont           - Continue execution until the next breakpoint\n"
                  //   << "  si, stepinto                - Step into the next instruction\n"
                  << "  exit, exit(), q             - Exit the debugger\n"
                  << "  bp, breakpoint <addr>       - Set a breakpoint at the specified address\n"
                  << "    - Address can be in hex (0x...) or decimal\n"
                  << "    - Address can be base+offset (e.g., base+0x100)\n"
                  << "  dump                        - Dump the current state of the registers\n"
                  << "  info breakpoint, info bp    - Show information about breakpoints\n"
                  << "  print <register>            - Print the value of the specified register\n"
                  << "  set <register> <value>      - Set the specified register to the given value\n"
                  << "    - Value must be in hex (0x...)\n"
                  << "  help                        - Show this help menu\n";
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