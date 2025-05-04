# Minimal GDB (mdb)
This is the main title of the README
`mdb` is a minimalist GDB-style debugger for ELF binaries. It supports essential debugging features like setting breakpoints, stepping through code, and disassembling instructions.

## Usage
```bash
./mdb ./binary
```
- Replace `./binary` with the path to the ELF executable you want to debug.
---

## Commands
You can interact with `mdb` using the following commands:
| Command               | Description |
|------------------------|-------------|
| `h`                   | Prints the help menu. |
| `r [args]`            | Reruns the program with optional `args`. If no arguments are given, the previous arguments are reused. |
| `c`                   | Continues execution from the current location. |
| `b 0*<addr>/symbol`   | Sets a breakpoint at a given address (hex, e.g., `0x400123`) or symbol. |
| `l`                   | Lists all set breakpoints. |
| `d [breakpoint]`      | Deletes the given breakpoint. If no argument is provided, deletes all breakpoints. |
| `si [steps]`          | Single-steps the specified number of steps. Defaults to 1 if not specified. |
| `disas`               | Disassembles 10 instructions from the current instruction pointer. |
| `clear`               | Clears screen. |
| `quit`                | Quits the debugger. |

## Automatic Disassembly
Every time execution pauses (due to a breakpoint or single step), `mdb` automatically disassembles and displays 10 instructions starting from the current instruction pointer.

## Requirements
- Capstone
- Libelf

## Build
```bash
make
```

## Notes
- `mdb` currently supports ELF binaries and provides basic breakpoint and stepping functionality.
- This is a learning/debugging tool and not meant to replace full-featured debuggers like GDB.
