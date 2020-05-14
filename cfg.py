import logging
import ghidra_bridge
import sys



class Control_Flow_Graph():
    def __init__(self):
        """Initialize the cfg of the target """
        logging.info("Initializing CFG")
        self.arch = None
        self.bits = None
        self.endian = None
        self.functions = []
        # one function is: {'address': xxxxx, 'blocks':[{'start_addr':xxxx, 'end_addr':xxxx, 'source': [FIXME],'dests': [startEA1 , startEA2 .. ]}, ..other blocks]}
        self.get_meta_data()
        self.populate_functions()

    def get_meta_data(self):
        """ Collects the metadata of the binary """
        logging.info("Collecting meta data")
        # getLanguage() returns something ligk 'x86/little/32/default'
        meta_data = str(currentProgram.getLanguage()).split('/')
        self.arch = meta_data[0]
        self.endian = meta_data[1]
        self.bits = meta_data[2]

    def get_function_blocks(self, function):
        """ checks all blocks in the function and creates the functions element:
        'blocks':[{'start_addr':xxxx, 'end_addr':xxxx, 'source': [startEA1 , startEA2 .. ],'dests': [startEA1 , startEA2 .. ]}, ..other blocks]
        """
        blocks = []
        block_model_iterator = ghidra.program.model.block.BasicBlockModel(currentProgram)
        function_addresses = function.getBody()
        code_blocks_iterator = block_model_iterator.getCodeBlocksContaining(function_addresses, monitor)

        # go through each block and populate the addresses, sources and destinations
        while code_blocks_iterator.hasNext():
            new_block = dict()
            block = code_blocks_iterator.next()
            # FIXME: block might have multiple start addresses, we ignore that here
            new_block['start_addr'] = block.getFirstStartAddress().getOffset()
            new_block['end_addr'] = block.getMaxAddress().getOffset()
            new_block['sources'] = []
            source_iterator = block.getSources(monitor)

            # collect all sources
            while source_iterator.hasNext():
                source = source_iterator.next()
                # FIXME: we are ignoring the information whether the source is in the same function or not (call to this function)
                new_block['sources'].append(source.getSourceAddress().getOffset())

            new_block['dests'] = []
            dest_iterator = block.getDestinations(monitor)

            # collect all destinations
            while dest_iterator.hasNext():
                dest = dest_iterator.next()
                # FIXME: we are ignoring the information whether the destination is in the same function or not (call other function)
                new_block['dests'].append(dest.getDestinationAddress().getOffset())
            

            blocks.append(new_block)
        
        return blocks


    def populate_functions(self):
        """ populates the functions attribute of the class """
        logging.info("Populating Functions")
        function = getFirstFunction()
        # iterate through all functions
        while function is not None:
            logging.debug("{} found at {}".format(function.getName(),function.getEntryPoint()))
            function_dict = {'address': function.getEntryPoint(), 'blocks': self.get_function_blocks(function)}
            self.functions.append(function_dict)
            function = getFunctionAfter(function)

    def print_cfg(self):
        logging.debug('Printing CFG')
        for f in self.functions:
            logging.debug("Function address {}".format(f['address']))
            for b in f['blocks']:
                logging.debug("----> Block address: start: {} end: {}".format(hex(b['start_addr']), hex(b['end_addr'])))
                for s in b['sources']:
                    logging.debug("---------> Source of this block: {}".format(hex(s)))
                for d in b['dests']:
                    logging.debug("---------> Destination of this block: {}".format(hex(d)))


def init_logger():
    logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.DEBUG)

    #fileHandler = logging.FileHandler("{0}/{1}.log".format(logPath, fileName))
    #fileHandler.setFormatter(logFormatter)
    #rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)


if __name__ == '__main__':
    init_logger()
    b = ghidra_bridge.GhidraBridge(namespace=globals()) # creates the bridge and loads the flat API into the global namespace

    cfg = Control_Flow_Graph()
    cfg.print_cfg()



""" For tests in interpreter:

b = ghidra_bridge.GhidraBridge(namespace=globals())
block_model_iterator = ghidra.program.model.block.BasicBlockModel(currentProgram)
function = getFirstFunction()
function_addresses = function.getBody()
code_blocks_iterator = block_model_iterator.getCodeBlocksContaining(function_addresses, monitor)
block = code_blocks_iterator.next()
new_block = dict()
block = code_blocks_iterator.next()
new_block['start_addr'] = block.getFirstStartAddress().getOffset()
new_block['end_addr'] = block.getMaxAddress().getOffset()
new_block['sources'] = []
source_iterator = block.getSources(monitor)
source = source_iterator.next()
new_block['sources'].append(source.getSourceAddress().getOffset())
"""