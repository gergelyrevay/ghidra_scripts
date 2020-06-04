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

public class pcode_find_const_parameters extends GhidraScript {
    
	/*
     * should return all source of the input varnode
     * cannot return only one source because we cannot decide which one is right
     * possible ends to the function:
     *	xxx COPY (const, ....) -> const
     *	CALL output -> not const
     *	getDef does not return anything -> comes outside of function FIXME: this must be checked
     *	BOOL* -> not const, it is a bool value
     *	INT_EQUAL
	 *  INT_NOTEQUAL
	 *	INT_LESS
	 *	INT_SLESS
	 *	INT_LESSEQUAL
	 *	INT_SLESSEQUAL
	 *	INT_CARRY
	 *	INT_SCARRY
	 *	INT_SBORROW
	 *	FLOAT_EQUAL
	 *	FLOAT_NOTEQUAL
	 *	FLOAT_LESS
	 *	FLOAT_LESSEQUAL
	 *	FLOAT_NAN -> all return bools, so not const
     *  BRANCH* -> we should not see branching because it does not have an output
     */
    public List<Varnode> getInputSources(PcodeOp pcodeOp) {
    	Varnode[] inputs; 
    	List<Varnode> retVal = new ArrayList<Varnode>();
    	
    	printf("[+] getInputSource: Seq: %s, Op: %s\n", pcodeOp.getSeqnum().toString(), pcodeOp.toString());
    	Varnode[] originalInputs = pcodeOp.getInputs();
    	for(Varnode input: originalInputs) {
	    	PcodeOp srcPcodeOp = input.getDef();
	    	
	    	switch (pcodeOp.getOpcode()) {
	
	        //	CALL output -> not const, we return the input varnode, there is no need to go further
	    	case PcodeOp.CALL:
	    		printf("[-] Input is the output of CALL, not searching further\n");
	    		retVal.add(input);
	    		break;
	    	// bool values ->  we return the input varnode, there is no need to go further   		
	        case PcodeOp.BOOL_NEGATE:
	        case PcodeOp.BOOL_XOR:
	        case PcodeOp.BOOL_AND:
	        case PcodeOp.BOOL_OR:
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
	    		printf("[-] Input is result of a Bool operation, not searching further\n");
	    		retVal.add(input);
	    		break;
	        //  BRANCH*, CALLIND -> we should not see branching because it does not have an output
	    	case PcodeOp.BRANCH:
	    	case PcodeOp.CBRANCH:
	    	case PcodeOp.BRANCHIND:
	    	case PcodeOp.CALLIND:
	    	case PcodeOp.RETURN:
	    		printf("[-] ERROR: Control Flow Instruction hit -> this should not happen\n");
	    	// usually there is a const in PTR manipulation, but we are not interested in that
	    	case PcodeOp.PTRADD:
	    	case PcodeOp.PTRSUB:
	    		printf("[-] PTRADD/SUB ignoring const and continue\n");
		    	//	getDef does not return anything -> comes outside of function FIXME: this must be checked
	    		if (input.isConstant()) {
	    			break;
	    		}
		    	if (srcPcodeOp == null) {
		    		printf("[-] getDef returned null, value come from outside the function, not searching further\n");
		    		retVal.add(input);
		    	} else {
		    		retVal.addAll(this.getInputSources(srcPcodeOp));
    			}
	    		break;
	    	//	xxx COPY (const, ....) -> const
	    	case PcodeOp.COPY:
	    		inputs = pcodeOp.getInputs();
	    		if (inputs[0].isConstant()) {
	    			printf("[-] COPY with const found, not searching further\n");
	    			retVal.add(inputs[0]);
	    			break;
	    		}
	    		//otherwise let it flow
	    	// in all other cases follow the inputs
	    	default:
	    		// printf("[-] Nothing found yet, keep backtracking\n");
		    	// getDef does not return anything -> comes outside of function FIXME: this must be checked
		    	if (srcPcodeOp == null) {
		    		printf("[-] getDef returned null, value come from outside the function, not searching further\n");
		    		retVal.add(input);
		    	} else {
		    		retVal.addAll(this.getInputSources(srcPcodeOp));
    			}
	    		break;
	    	
	    	}
    	}
    	return retVal;
    	
    }
    
    /* in the current state simply dumps the provided Varnode list */
    public void printConstVarnodes(List<Varnode> varnodes) {
      for(Varnode vr: varnodes) {
		// This is one of the stupidest hack ever. For some reason getDataContain does not like
		// input.getAddress() as a parameter, but if we convert the input.getAddress to a string
		// and init a new Address with that, then it is fine 
    	// String addr = String.format("%x",vr.getAddress().getOffset());
    	// Address addrObj = currentProgram.getAddressFactory().getAddress(addr);
    	// Data data = getDataContaining(addrObj);
		printf("   [+] %s\n", vr.toString());

	}
    }
    	
    /* searches CALL operations in the function, and backtracks each parameter of the CALL to find out
     * if they rely on static/constant values
     */
	public void find_const_conditions(HighFunction hf){
        
        Iterator<PcodeOpAST> opiter = hf.getPcodeOps();

        List<Varnode> constantSources = new ArrayList<Varnode>();
        

        while(opiter.hasNext()){
            PcodeOpAST pcode_op = opiter.next();
            Varnode[] inputs = pcode_op.getInputs();
//			printf("seq: %s, OP: %s\n ", pcode_op.getSeqnum().toString(), pcode_op.toString());
			if(pcode_op.getOpcode() == PcodeOp.CALL) {
				for(int i = 1; i < inputs.length; i++) {
					printf("[-] checking input: %s Space %d\n", inputs[i].toString(), inputs[i].getSpace());
					if (inputs[i].isConstant()) {
						printf("[+] Constant found: %s\n", inputs[i].toString());
						constantSources.add(inputs[i]);
					} else {
							List<Varnode> sources = this.getInputSources(inputs[i].getDef());
							for(Varnode src: sources) {
//								printf("[+] Src: %s\n", src.toString());
								if (src.isConstant()) {
									constantSources.add(src);
								}
							}
					}
				}
				if (!constantSources.isEmpty()) {
					printf("[+] CALL at Seq: %s OP: %s, depends on the following constants:\n", pcode_op.getSeqnum().toString(), pcode_op.toString());
					this.printConstVarnodes(constantSources);
					constantSources.clear();
				}
			}
        }
        
	}


    public void run() throws Exception {
    	//FIXME: main function is hardcoded: this address must be changed other binary is tested
        Address addr = currentProgram.getAddressFactory().getAddress("0010080a");
        Function func = getFunctionContaining(addr);

        DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
        
		if ( !ifc.openProgram(this.currentProgram) ) {
			throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
		}
		ifc.setSimplificationStyle("decompile");
		DecompileResults res = ifc.decompileFunction(func, 30, null);
        HighFunction high = res.getHighFunction();

        find_const_conditions(high);
    }

}
