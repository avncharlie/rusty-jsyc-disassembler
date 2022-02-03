# Rusty-JSYC-disassembler

Disassemble and modify bytecode generated with [Rusty-JSYC](https://github.com/jwillbold/rusty-jsyc).

```
./disassembler.py bytecode_file [action]*
File to disassemble must be provided.
Any amount of actions can be listed afterwards.
If no actions provided, the display_basic action will trigger.

Examples:
  $ ./disassembler.py file display_fancy
  Display disassembly of file

  $ ./disassembler.py file NOPify export_bytecode
  Export NOPIfied bytecode of file

  $ ./disassembler.py file NOPify NOPify export_bytecode
  Export doubly NOPIfied bytecode of file

  $ ./disassembler.py file display_fancy obf_strings display_fancy
  1. Display disassembly of file
  2. Obfuscate strings in bytecode
  3. Display disassembly of file (modified from string obfuscation)

Parameters
  bytecode_file: file of Rusty-JSYC base64 encoded bytecode

  actions:
    display_basic: Display basic disassembly of bytecode
    display_fancy: Display disassembly of bytecode with labels
    NOPify: Disperse NOPs throughout loaded bytecode
    obf_strings: Obfuscate strings present in loaded bytecode
    export: Export loaded bytecode (base64 encrypted) to paste into vm
    jumps: Display jump table of loaded bytecode
```
