# Ghidra Script

A place for me to dump scripts.

## cfg.py:
Experimental script with the Ghidra API. It uses ghidra_bridge instead of running it directly with Ghidra. This allows the usage of Python3. Ghidra should be started in headless mode:
```
$ ghidra_9.1.2_PUBLIC/support/analyzeHeadless [project folder] -import [analysed binary] -scriptPath [path to script] -postScript ghidra_bridge_server.py -overWrite
```
The script dumps the control flow graph in the sense that it loads every function, every block, and every source and destination to each block.
```
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  Function address 080485ac
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ----> Block address: start: 0x80485ac end: 0x80485c4
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ---------> Source of this block: 0x8049030
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ---------> Destination of this block: 0x80487a0
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ---------> Destination of this block: 0x80485ca
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ---------> Destination of this block: 0x80485c5
```


## print_pcode.java:
Example script on how to setup the decompiler to access the P-Code (Ghidra IL) code of a specified function. A memory address from the target function should be added in the code.

Output:
```
print_pcode.java> Running...
seq: (ram, 0x1006f5, 19, 0), OP:  ---  CALL (ram, 0x1005a0, 8) , (const, 0x1007b4, 8)
seq: (ram, 0x1006fa, 22, 1), OP: (register, 0x0, 4) CALL (ram, 0x1005b0, 8)
seq: (ram, 0x100706, 46, 2), OP: (register, 0x206, 1) INT_EQUAL (register, 0x0, 4) , (const, 0x37, 4)
seq: (ram, 0x10070a, 48, 3), OP:  ---  CBRANCH (ram, 0x10071a, 1) , (register, 0x206, 1)
seq: (ram, 0x100713, 52, 0), OP:  ---  CALL (ram, 0x100590, 8) , (const, 0x1007c6, 8)
seq: (ram, 0x100718, 53, 1), OP:  ---  BRANCH (ram, 0x100726, 1)
seq: (ram, 0x100721, 64, 0), OP:  ---  CALL (ram, 0x100590, 8) , (const, 0x1007cf, 8)
seq: (ram, 0x100726, 54, 0), OP: (register, 0x0, 8) COPY (const, 0x0, 8)
seq: (ram, 0x10072c, 60, 1), OP:  ---  RETURN (const, 0x0, 8) , (register, 0x0, 8)
print_pcode.java> Finished!
```