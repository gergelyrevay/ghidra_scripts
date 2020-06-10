//Test script to see how to create a Control Flow Graph of a function as a GDirectedGraph. With the GDirectedGraph the graph algorithms in the Ghidra API can be used. Note that the entry point of the function is hardcoded, so that must be changed according to the target binary.
//@author 
//@category CodeAnalysis
//@keybinding 
//@menupath 
//@toolbar 

//FIXME: many of the default imports are not needed
import ghidra.app.script.GhidraScript;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphFactory;
import ghidra.program.model.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import java.util.*;

public class ControlFlowGraphTest extends GhidraScript {

	/*
	 * Creates a new control flow graph for a function.
	 * Vertex: a Basic Block as CodeBlockVertex
	 * Edge: connection between basic blocks as CodeBlockEdge
	 * 
	 */
	public class FunctionControlFlowGraph {
		protected GDirectedGraph<CodeBlockVertex, CodeBlockEdge> cfg;
		protected Function function;

		protected GDirectedGraph<CodeBlockVertex, CodeBlockEdge> createGraph() {
			return GraphFactory.createDirectedGraph();
		}
		
		/*
		 * Dummy constructor
		 */
		public FunctionControlFlowGraph() {
			this.cfg = this.createGraph(); 
		}
		
		/*
		 * Creates a control flow graph for the input function
		 */
		public FunctionControlFlowGraph(Function function) {
			this.cfg = this.createGraph();
			this.function = function;
			BasicBlockModel basicBlockModel = new BasicBlockModel(currentProgram);
			AddressSetView addrSet = function.getBody();
			try {
				CodeBlockIterator codeBlockIter = basicBlockModel.getCodeBlocksContaining(addrSet, getMonitor());
			
				 // go through each block and add the outgoing edges to the graph
				while (codeBlockIter.hasNext()) {
					CodeBlock block = codeBlockIter.next();
					CodeBlockReferenceIterator dstBlocks = block.getDestinations(getMonitor());
					
					//using the CodeBlockReference to add each edge
					while (dstBlocks.hasNext()) {
						this.addEdge(dstBlocks.next());
					}
					
				}
			} catch (CancelledException e) {
				e.printStackTrace();
			}

		}
		
		/*
		 * Helper function to print a Vertex and its successors
		 */
		public void printVertex(CodeBlockVertex codeBlockVertex) {
			printf("[+] Code Block Start Address: 0x%x\n", codeBlockVertex.getCodeBlock().getFirstStartAddress().getOffset());
			Collection<CodeBlockVertex> successors = cfg.getSuccessors(codeBlockVertex);
			for(CodeBlockVertex cbv: successors) {
				printf("[-] -----> Successor Block at: 0x%x\n", cbv.getCodeBlock().getFirstStartAddress().getOffset());
			}
		}
		
		/*
		 * Simple dumping of the CFG just for validation
		 */
		public void printFCFG() {
			Address entryPoint = this.function.getEntryPoint();
			BasicBlockModel basicBlockModel = new BasicBlockModel(currentProgram);
			printf("[+] Printing CFG for Function at: 0x%x\n", this.function.getEntryPoint().getOffset());
			try {
				CodeBlock entryBlock = basicBlockModel.getCodeBlockAt(entryPoint, getMonitor());
				CodeBlockVertex entryVertex = new CodeBlockVertex(entryBlock);
				List<CodeBlockVertex> vertexBuffer = new ArrayList<CodeBlockVertex>();
				vertexBuffer.add(entryVertex);
				int i = 0;
				while (i < vertexBuffer.size()) {
					this.printVertex(vertexBuffer.get(i));
					vertexBuffer.addAll(cfg.getSuccessors(vertexBuffer.get(i)));
					i++;
				}
				
			} catch (CancelledException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
						
		}
		/*
		 * creates an edge using a CodeBlockReference, that has all the necessary information for the edge
		 * FIXME: we might need to handle if the edge is a result of CALL and dest code block is in a different function
		 */
		public void addEdge(CodeBlockReference codeBlockRef) {
			CodeBlockEdge edge = new CodeBlockEdge(new CodeBlockVertex(codeBlockRef.getSourceBlock()), new CodeBlockVertex(codeBlockRef.getDestinationBlock()));
			this.cfg.addEdge(edge);
		}
		
		public void addEdge(CodeBlock srcBlock, CodeBlock dstBlock) {
			CodeBlockEdge edge = new CodeBlockEdge(new CodeBlockVertex(srcBlock), new CodeBlockVertex(dstBlock));
			this.cfg.addEdge(edge);
		}
	}
	
    public void run() throws Exception {
    	//FIXME: change address in this line to the start address of the function you want to analyze.
        Address addr = currentProgram.getAddressFactory().getAddress("0010080a");
        Function func = getFunctionContaining(addr);
    	
        FunctionControlFlowGraph fcfg = new FunctionControlFlowGraph(func);
        fcfg.printFCFG();
        
    }

}
