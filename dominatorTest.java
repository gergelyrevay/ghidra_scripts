// This is just an experimental script to try whether the dominator algorithms can be used without the GraphService. Spoiler, it can be. Most of the code is copy-past from ghidra test code, to be precise from the GraphAlgorithmsTest.java and its parent class. Note that this script does not print anything, the goal is that setV at the end contains the expected nodes(in comment). This can be validated with a debugger. Also the start address is hardcoded, you need to change it if you want to use it with your own code. 
//@author 
//@category Testing
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
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;

import ghidra.graph.*;
import ghidra.graph.algo.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.TimeoutException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;


public class dominatorTest extends GhidraScript {

	protected GDirectedGraph<TestV, TestE> g;

	// Just a wrapper class for Vertices
    protected static class TestV {

	    private String id;
	
	    public TestV(String id) {
	            this.id = id;
	    }
	
	    public TestV(int id) {
	            this.id = Integer.toString(id);
	    }

    }
    
    // Just a wrapper class for edges
    protected static class TestE extends DefaultGEdge<TestV> {

        public TestE(TestV start, TestV end) {
                super(start, end);
        }
    }

	protected TestV vertex(int id) {
	        return new TestV(id);
	}
	
	protected TestV vertex(String id) {
	        return new TestV(id);
	}
	
	// note: this function automatically adds the edge to the graph
	protected TestE edge(TestV start, TestV end) {
	        TestE e = new TestE(start, end);
	        g.addEdge(e);
	        return e;
	}
	
	protected String id(TestV v) {
	        return v.id;
	}

	protected GDirectedGraph<TestV, TestE> createGraph() {
		return GraphFactory.createDirectedGraph();
	}
	
	public void testDominance_GetDominators() throws CancelledException {

		/*
		 * Creating the following graph:
		 		v1->.		 		
		 		 |  |
		 		v2  |
		 		 |  |
		 		v3  |
		 		 |  |
		 		v4--<
		 */
		g = this.createGraph();
		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v1, v4);

		ChkDominanceAlgorithm<TestV, TestE> algo =
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		// get dominators for each vertex.
		Set<TestV> setV = algo.getDominators(v1);// v1
		setV = algo.getDominators(v2);// v1, v2
		setV = algo.getDominators(v3);// v1, v2, v3
		setV = algo.getDominators(v4);// v1, v4
	}	
	
    public void run() throws Exception {
    	testDominance_GetDominators();
    }

}
