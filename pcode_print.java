//TODO write a description for this script
//@author 
//@category PCode
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.graph.*;
import ghidra.app.decompiler.*;

import java.util.*;

public class pcode_test extends GhidraScript {

    public void print_pcode(HighFunction hf){
        Iterator<PcodeOpAST> opiter = hf.getPcodeOps();

        while(opiter.hasNext()){
            PcodeOpAST pcode_op = opiter.next();
            //Printing sequence number and Pcode
            printf("seq: %s, OP: %s\n", pcode_op.getSeqnum().toString(), pcode_op.toString());

        }
    }

    public void run() throws Exception {
        //An address from the function we want to analyse
        Address addr = currentProgram.getAddressFactory().getAddress("00100702");
        Function func = getFunctionContaining(addr);

        //Initialize Decompiler
        DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
        
		if ( !ifc.openProgram(this.currentProgram) ) {
			throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
		}
		ifc.setSimplificationStyle("normalize");
		DecompileResults res = ifc.decompileFunction(func, 30, null);

        //Get higher representation of the function
        HighFunction high = res.getHighFunction();

        print_pcode(high);



    }

}
