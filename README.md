# Debugger

This is my first debugger which uses libelfin and linenoise.
Currentle it is a simple command-line debugger with basic functionality for controlling program execution, managing breakpoints, and inspecting/modifying register values. 

## How to install

1. Download this repositry using
    
    ```bash
    git clone [https://github.com/K1r4-021/My_debugger.git](https://github.com/K1r4-021/My_debugger.git)
    ```
    
2. Enter the Directory 
    
    ```bash
    cd My_debugger
    ```
    
3. compile the debugger using cmake
    
    ```bash
    cmake -B build
    cmake --build build
    ```
    

## Commands

- To run

```bash
./My_debugger <program_name>
```

- Continue execution until the next breakpoint.
```bash
continue, c, cont
```

- Exit the debugger.
```bash
exit, exit(), q
```

- Set a breakpoint at the specified address.
```bash
bp, breakpoint <addr>
```
<aside>
💡 Address can be in hexadecimal format (`0x...`) or decimal.
Address can also be specified as `base+offset` (e.g., `base+0x100`).
</aside>

- Dump the current state of the registers.
```bash
dump
```

- Print the value of the specified register name.
```bash
print <register>
```

- Set the specified register to the given value.
```bash
set <register> <value>
```

- Show information about breakpoints.
```bash
info breakpoint, info bp
```

- Show the help menu.
```bash
help
```

## Contributing
Feel free to open issues or submit pull requests if you find any bugs or have suggestions for new features.
