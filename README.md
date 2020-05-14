# Ghidra Script

A place for me to dump scripts.

## cfg.py:
Experimental script with the Ghidra API. It uses ghidra_bridge instead of running it directly with Ghidra. This allows the usage of Python3. Ghidra should be started in headless mode:
```
$ ghidra_9.1.2_PUBLIC/support/analyzeHeadless [project folder] -import [analysed binary] -scriptPath [path to script] -postScript ghidra_bridge_server.py -overWrite
```
The script dumps the control flow graph in the sense that it loads every function, every block, and every source and destination to each block.
````
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  Function address 080485ac
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ----> Block address: start: 0x80485ac end: 0x80485c4
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ---------> Source of this block: 0x8049030
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ---------> Destination of this block: 0x80487a0
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ---------> Destination of this block: 0x80485ca
2020-05-13 06:49:01,600 [MainThread  ] [DEBUG]  ---------> Destination of this block: 0x80485c5
```