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

## pcode_find_const_parameters.java
Experimental script to find whether the parameters of a CALL pcode operation can be traced back to a constant value. It takes a function looks for all CALLs then evaluates its parameters. At the end dumps all constant values that the CALL depends on. I used this script to play with backtracing.

Output:
```
pcode_op_play.java> Running...
[-] checking input: (unique, 0x100000ab, 8) Space 291
[+] getInputSource: Seq: (ram, 0x100834, 460, 3), Op: (unique, 0x100000ab, 8) COPY (const, 0x100974, 8)
[-] COPY with const found, not searching further
[+] CALL at Seq: (ram, 0x100834, 31, 7) OP:  ---  CALL (ram, 0x1006c0, 8) , (unique, 0x100000ab, 8), depends on the following constants:
   [+] (const, 0x100974, 8)
[-] checking input: (unique, 0x620, 8) Space 291
[+] getInputSource: Seq: (ram, 0x100840, 465, 8), Op: (unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffc8, 8)
[-] PTRADD/SUB ignoring const and continue
[-] getDef returned null, value come from outside the function, not searching further
[-] PTRADD/SUB ignoring const and continue
[-] checking input: (const, 0x20, 4) Space 48
[+] Constant found: (const, 0x20, 4)
[-] checking input: (ram, 0x301010, 8) Space 433
[+] getInputSource: Seq: (ram, 0x100834, 365, 5), Op: (ram, 0x301010, 8) INDIRECT (ram, 0x301010, 8) , (const, 0x1f, 4)
[-] getDef returned null, value come from outside the function, not searching further
[-] getDef returned null, value come from outside the function, not searching further
[+] CALL at Seq: (ram, 0x10084c, 39, 12) OP:  ---  CALL (ram, 0x1006d0, 8) , (unique, 0x620, 8) , (const, 0x20, 4) , (ram, 0x301010, 8), depends on the following constants:
   [+] (const, 0x20, 4)
   [+] (const, 0x1f, 4)
[-] checking input: (unique, 0x620, 8) Space 291
[+] getInputSource: Seq: (ram, 0x100851, 466, 13), Op: (unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffc8, 8)
[-] PTRADD/SUB ignoring const and continue
[-] getDef returned null, value come from outside the function, not searching further
[-] PTRADD/SUB ignoring const and continue
[-] checking input: (unique, 0x620, 8) Space 291
[+] getInputSource: Seq: (ram, 0x10087e, 475, 1), Op: (unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffc8, 8)
[-] PTRADD/SUB ignoring const and continue
[-] getDef returned null, value come from outside the function, not searching further
[-] PTRADD/SUB ignoring const and continue
[-] checking input: (unique, 0x100000b3, 8) Space 291
[+] getInputSource: Seq: (ram, 0x10088c, 461, 2), Op: (unique, 0x100000b3, 8) COPY (const, 0x100987, 8)
[-] COPY with const found, not searching further
[+] CALL at Seq: (ram, 0x10088c, 95, 6) OP: (register, 0x0, 4) CALL (ram, 0x1006e0, 8) , (unique, 0x620, 8) , (unique, 0x100000b3, 8), depends on the following constants:
   [+] (const, 0x100987, 8)
[-] checking input: (unique, 0x100000bb, 8) Space 291
[+] getInputSource: Seq: (ram, 0x10089c, 462, 0), Op: (unique, 0x100000bb, 8) COPY (const, 0x10098e, 8)
[-] COPY with const found, not searching further
[+] CALL at Seq: (ram, 0x10089c, 106, 4) OP:  ---  CALL (ram, 0x100690, 8) , (unique, 0x100000bb, 8), depends on the following constants:
   [+] (const, 0x10098e, 8)
[-] checking input: (unique, 0x100000c3, 8) Space 291
[+] getInputSource: Seq: (ram, 0x1008b6, 463, 1), Op: (unique, 0x100000c3, 8) COPY (const, 0x100997, 8)
[-] COPY with const found, not searching further
[-] checking input: (unique, 0x620, 8) Space 291
[+] getInputSource: Seq: (ram, 0x1008a3, 476, 0), Op: (unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffc8, 8)
[-] PTRADD/SUB ignoring const and continue
[-] getDef returned null, value come from outside the function, not searching further
[-] PTRADD/SUB ignoring const and continue
[+] CALL at Seq: (ram, 0x1008b6, 138, 5) OP:  ---  CALL (ram, 0x1006c0, 8) , (unique, 0x100000c3, 8) , (unique, 0x620, 8), depends on the following constants:
   [+] (const, 0x100997, 8)
[-] checking input: (unique, 0x100000cb, 8) Space 291
[+] getInputSource: Seq: (ram, 0x1008c2, 464, 6), Op: (unique, 0x100000cb, 8) COPY (const, 0x1009a4, 8)
[-] COPY with const found, not searching further
[+] CALL at Seq: (ram, 0x1008c2, 142, 10) OP:  ---  CALL (ram, 0x100690, 8) , (unique, 0x100000cb, 8), depends on the following constants:
   [+] (const, 0x1009a4, 8)
pcode_op_play.java> Finished!
```

## pcode_influence_branching.java

Experimental script to analyse whether the output of a function call influences branching in the callee function. Also checks whether the output is compared with 0.

Output:
```
pcode_influence_branching.java> Running...
seq: (ram, 0x100834, 31, 7), OP:  ---  CALL (ram, 0x1006c0, 8) , (unique, 0x100000ab, 8)
seq: (ram, 0x10084c, 39, 12), OP:  ---  CALL (ram, 0x1006d0, 8) , (unique, 0x620, 8) , (const, 0x20, 4) , (ram, 0x301010, 8)
seq: (ram, 0x100858, 45, 17), OP: (register, 0x0, 8) CALL (ram, 0x1006a0, 8) , (unique, 0x620, 8)
seq: (ram, 0x10088c, 95, 6), OP: (register, 0x0, 4) CALL (ram, 0x1006e0, 8) , (unique, 0x620, 8) , (unique, 0x100000b3, 8)
[=] influenceBranching: zerocompare yes: seq: (ram, 0x100891, 100, 7), OP: (register, 0x206, 1) INT_EQUAL (register, 0x0, 4) , (const, 0x0, 4)
[=] influenceBranching: iscompare yes at: seq: (ram, 0x100891, 100, 7), OP: (register, 0x206, 1) INT_EQUAL (register, 0x0, 4) , (const, 0x0, 4)
[=] influenceBranching: isCondBranch yes at: seq: (ram, 0x100893, 102, 8), OP:  ---  CBRANCH (ram, 0x1008a3, 1) , (register, 0x206, 1)
[+] Does influence branching
[+] Does zero compare
seq: (ram, 0x10089c, 106, 4), OP:  ---  CALL (ram, 0x100690, 8) , (unique, 0x100000bb, 8)
seq: (ram, 0x1008b6, 138, 5), OP:  ---  CALL (ram, 0x1006c0, 8) , (unique, 0x100000c3, 8) , (unique, 0x620, 8)
seq: (ram, 0x1008c2, 142, 10), OP:  ---  CALL (ram, 0x100690, 8) , (unique, 0x100000cb, 8)
seq: (ram, 0x1008db, 122, 2), OP:  ---  CALL (ram, 0x1006b0, 8)
pcode_influence_branching.java> Finished!
```

## dominatorTest.java

This is just an experimental script to try whether the dominator algorithms can be used without the GraphService(GraphService is not included in the open source version). Spoiler, it can be. Most of the code is copy-paste from ghidra test code, to be precise from the GraphAlgorithmsTest.java and its parent class. Note that this script does not print anything, the goal is that setV at the end contains the expected nodes(in comment). This can be validated with a debugger.

Some references:
https://ghidra.re/ghidra_docs/api/ghidra/util/graph/Dominator.html
https://ghidra.re/ghidra_docs/api/ghidra/graph/algo/ChkDominanceAlgorithm.html

## ControlFlowGraphTest.java

Test script to see how to create a Control Flow Graph of a function as a GDirectedGraph. With the GDirectedGraph the graph algorithms in the Ghidra API can be used. Note that the entry point of the function is hardcoded, so that must be changed according to the target binary.

Output:
```
ControlFlowGraphTest.java> Running...
[+] Printing CFG for Function at: 0x10080a
[+] Code Block Start Address: 0x10080a
[-] -----> Successor Block at: 0x10087e
[-] -----> Successor Block at: 0x100871
[-] -----> Successor Block at: 0x1006c0
[-] -----> Successor Block at: 0x1006d0
[-] -----> Successor Block at: 0x1006a0
[+] Code Block Start Address: 0x10087e
[-] -----> Successor Block at: 0x100895
[-] -----> Successor Block at: 0x1008a3
[-] -----> Successor Block at: 0x1006e0
[+] Code Block Start Address: 0x100871
[-] -----> Successor Block at: 0x10087e
[+] Code Block Start Address: 0x1006c0
[+] Code Block Start Address: 0x1006d0
[+] Code Block Start Address: 0x1006a0
[+] Code Block Start Address: 0x100895
[-] -----> Successor Block at: 0x1008c7
[-] -----> Successor Block at: 0x100690
[+] Code Block Start Address: 0x1008a3
[-] -----> Successor Block at: 0x1008c7
[-] -----> Successor Block at: 0x1006c0
[-] -----> Successor Block at: 0x100690
[+] Code Block Start Address: 0x1006e0
[+] Code Block Start Address: 0x10087e
[-] -----> Successor Block at: 0x100895
[-] -----> Successor Block at: 0x1008a3
[-] -----> Successor Block at: 0x1006e0
[+] Code Block Start Address: 0x1008c7
[-] -----> Successor Block at: 0x1008db
[-] -----> Successor Block at: 0x1008e0
[+] Code Block Start Address: 0x100690
[+] Code Block Start Address: 0x1008c7
[-] -----> Successor Block at: 0x1008db
[-] -----> Successor Block at: 0x1008e0
[+] Code Block Start Address: 0x1006c0
[+] Code Block Start Address: 0x100690
[+] Code Block Start Address: 0x100895
[-] -----> Successor Block at: 0x1008c7
[-] -----> Successor Block at: 0x100690
[+] Code Block Start Address: 0x1008a3
[-] -----> Successor Block at: 0x1008c7
[-] -----> Successor Block at: 0x1006c0
[-] -----> Successor Block at: 0x100690
[+] Code Block Start Address: 0x1006e0
[+] Code Block Start Address: 0x1008db
[-] -----> Successor Block at: 0x1006b0
[+] Code Block Start Address: 0x1008e0
[+] Code Block Start Address: 0x1008db
[-] -----> Successor Block at: 0x1006b0
[+] Code Block Start Address: 0x1008e0
[+] Code Block Start Address: 0x1008c7
[-] -----> Successor Block at: 0x1008db
[-] -----> Successor Block at: 0x1008e0
[+] Code Block Start Address: 0x100690
[+] Code Block Start Address: 0x1008c7
[-] -----> Successor Block at: 0x1008db
[-] -----> Successor Block at: 0x1008e0
[+] Code Block Start Address: 0x1006c0
[+] Code Block Start Address: 0x100690
[+] Code Block Start Address: 0x1006b0
[+] Code Block Start Address: 0x1006b0
[+] Code Block Start Address: 0x1008db
[-] -----> Successor Block at: 0x1006b0
[+] Code Block Start Address: 0x1008e0
[+] Code Block Start Address: 0x1008db
[-] -----> Successor Block at: 0x1006b0
[+] Code Block Start Address: 0x1008e0
[+] Code Block Start Address: 0x1006b0
[+] Code Block Start Address: 0x1006b0
ControlFlowGraphTest.java> Finished!

```