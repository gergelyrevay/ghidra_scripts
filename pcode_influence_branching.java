//TODO write a description for this script
//@author 
//@category PCode
//@keybinding 
//@menupath 
//@toolbar 

import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
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

public class pcode_influence_branching extends GhidraScript {

	
	/*
	 * Class to store the results of the analysis.
	 */
	class CallConsequences{
		Boolean isInfluenceBranching;
		Boolean isZeroCompare;
	
	
		public CallConsequences() {
			this.isInfluenceBranching = false;
			this.isZeroCompare = false;
		}
		
		public Boolean getIsInfluenceBranching() {
			return isInfluenceBranching;
		}
	
		public void setIsInfluenceBranching(Boolean isInfluenceBranching) {
			this.isInfluenceBranching = isInfluenceBranching;
		}
	
		public Boolean getIsZeroCompare() {
			return isZeroCompare;
		}
	
		public void setIsZeroCompare(Boolean isZeroCompare) {
			this.isZeroCompare = isZeroCompare;
		}
	}

	/*
	 * checks if the Pcode Op is a comparison
	 */
	Boolean isCompare(PcodeOp pcodeOp) 	{
		switch (pcodeOp.getOpcode()){
		    case PcodeOp.INT_EQUAL:
			case PcodeOp.INT_NOTEQUAL:
			case PcodeOp.INT_LESS:
			case PcodeOp.INT_SLESS:
			case PcodeOp.INT_LESSEQUAL:
			case PcodeOp.INT_SLESSEQUAL:
			case PcodeOp.INT_CARRY:
			case PcodeOp.INT_SCARRY:
			case PcodeOp.INT_SBORROW:
			case PcodeOp.FLOAT_EQUAL:
			case PcodeOp.FLOAT_NOTEQUAL:
			case PcodeOp.FLOAT_LESS:
			case PcodeOp.FLOAT_LESSEQUAL:
			case PcodeOp.FLOAT_NAN:
				return true;
		}
		return false;
	}
	
	/* 
	 * checking if the operation is a compare against 0
	 */
	Boolean isZeroCompare(PcodeOp pcodeOp) {
		if (this.isCompare(pcodeOp)) {
			Varnode[] inputs = pcodeOp.getInputs();
			for (Varnode input: inputs) {
				if (input.isConstant() && input.getOffset() == 0) {
					return true;
				}
			}
			
		}
		return false;
	}
	
	/*
	 * checks if the given Varnode is used as an input in the give Pcode Operation
	 */
	Boolean isInput(PcodeOp pcodeOp, Varnode vn) {
		Varnode[] inputs = pcodeOp.getInputs();
		if (inputs.length == 0) {return false;}
		for (Varnode input: inputs) {
			if(input.equals(vn)) {return true;}
		}
		return false;
	}
	
	/*
	 * Checks if the Pcode Op  is a conditional branch.
	 */
	Boolean isCondBranch(PcodeOp pcodeOp) {
		
		if (pcodeOp.getOpcode() == PcodeOp.CBRANCH ){return true;}
		return false;
	}
	
	/*
	 *  checks whether the return value of the function call is used to influence branching 
	 */
	CallConsequences isInfluenceBranching(PcodeOpAST pcodeOp) {
		CallConsequences retVal = new CallConsequences();
		//check if targetFunction returns something
		// in pcode one see if there is a return value
		Varnode output = pcodeOp.getOutput();
		if (output != null) {
			//check if return value used in branching
			Iterator<PcodeOp> testiter = pcodeOp.getBasicIter();
			
			//check next two function whether it is comparison and branching
			if (testiter.hasNext()){
				PcodeOp nextPcodeOp = testiter.next();
				
				// Checking if the output of the operation is the input of the next function and whether it is a zero comparison
				if (this.isZeroCompare(nextPcodeOp) && this.isInput(nextPcodeOp, output)) {
					retVal.setIsZeroCompare(true);
					printf("[=] influenceBranching: zerocompare yes: seq: %s, OP: %s\n", nextPcodeOp.getSeqnum().toString(), nextPcodeOp.toString());
				}
				
				// Checking if the next operation is a comparison and the output is used as an input
				if (this.isCompare(nextPcodeOp) && this.isInput(nextPcodeOp, output) && testiter.hasNext()) {
					printf("[=] influenceBranching: iscompare yes at: seq: %s, OP: %s\n", nextPcodeOp.getSeqnum().toString(), nextPcodeOp.toString());
					output = nextPcodeOp.getOutput();
					PcodeOp nextnextPcodeOp = testiter.next();
					
					// Checking if the second operation is a conditional branch based on the output of the comparison
					if (this.isCondBranch(nextnextPcodeOp) && this.isInput(nextnextPcodeOp, output)) {
						retVal.setIsInfluenceBranching(true);
						printf("[=] influenceBranching: isCondBranch yes at: seq: %s, OP: %s\n", nextnextPcodeOp.getSeqnum().toString(), nextnextPcodeOp.toString());
					}
				}				
			}			
		}
		return retVal;
	}
	
    public void print_pcode(HighFunction hf){
        Iterator<PcodeOpAST> opiter = hf.getPcodeOps();

        while(opiter.hasNext()){
            PcodeOpAST pcode_op = opiter.next();
            //Printing sequence number and Pcode
			if(pcode_op.getOpcode() == PcodeOp.CALL) {
				printf("seq: %s, OP: %s\n", pcode_op.getSeqnum().toString(), pcode_op.toString());
				CallConsequences callCons = this.isInfluenceBranching(pcode_op);
				
				if (callCons.getIsInfluenceBranching()) {
					printf("[+] Does influence branching\n");
				}
				if (callCons.getIsZeroCompare()) {
					printf("[+] Does zero compare\n");
				}
				
			}

        }
    }

    public void run() throws Exception {
        //An address from the function we want to analyse
        Address addr = currentProgram.getAddressFactory().getAddress("0010080a");
        Function func = getFunctionContaining(addr);

        //Initialize Decompiler
        DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
        
		if ( !ifc.openProgram(this.currentProgram) ) {
			throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
		}
		ifc.setSimplificationStyle("decompile");
		DecompileResults res = ifc.decompileFunction(func, 30, null);

        //Get higher representation of the function
        HighFunction high = res.getHighFunction();

        print_pcode(high);



    }

}