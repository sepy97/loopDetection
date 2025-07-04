import io
import os
import sys
import argparse

class BasicBlock:
    """
    Represents a basic block in the Control Flow Graph.
    A basic block is a sequence of straight-line code with no branches in,
    except to the entry, and no branches out, except at the exit.
    """
    def __init__(self, start_pc):
        self.start_pc = start_pc
        self.end_pc = None
        self.instructions = []
        # Successors are identified by their start_pc
        self.successors = []

    def __repr__(self):
        return f"BasicBlock(start_pc={hex(self.start_pc)}, end_pc={hex(self.end_pc) if self.end_pc else 'N/A'})"

class CFG:
    """
    Represents the Control Flow Graph.
    It contains a dictionary of basic blocks, indexed by their starting PC.
    """
    def __init__(self):
        self.blocks = {}
        self.start_node = None

    def add_block(self, block):
        """Adds a basic block to the CFG."""
        if not self.blocks:
            self.start_node = block.start_pc
        self.blocks[block.start_pc] = block

    def find_loops(self):
        """
        Finds all loops in the CFG using Tarjan's algorithm for finding
        Strongly Connected Components (SCCs). Each SCC with more than one node,
        or a single node with a self-edge, represents a loop.
        """
        if not self.blocks:
            return []

        self.index = 0
        self.stack = []
        self.on_stack = set()
        self.indices = {}
        self.low_link = {}
        self.sccs = []

        for node_pc in self.blocks:
            if node_pc not in self.indices:
                self._tarjan(node_pc)

        # Filter SCCs to find only those that represent loops
        loops = []
        for scc in self.sccs:
            is_loop = False
            if len(scc) > 1:
                is_loop = True
            elif len(scc) == 1:
                # A single-node SCC is a loop if it has a self-edge
                node = scc[0]
                if node in self.blocks.get(node, BasicBlock(0)).successors:
                    is_loop = True
            
            if is_loop:
                loops.append(scc)
        
        return loops

    def _tarjan(self, node_pc):
        """Recursive helper for Tarjan's algorithm."""
        self.indices[node_pc] = self.index
        self.low_link[node_pc] = self.index
        self.index += 1
        self.stack.append(node_pc)
        self.on_stack.add(node_pc)

        block = self.blocks.get(node_pc)
        if not block:
            return

        for successor_pc in block.successors:
            if successor_pc not in self.indices:
                # Successor has not yet been visited, recurse on it
                self._tarjan(successor_pc)
                self.low_link[node_pc] = min(self.low_link[node_pc], self.low_link[successor_pc])
            elif successor_pc in self.on_stack:
                # Successor is on the stack and hence in the current SCC
                self.low_link[node_pc] = min(self.low_link[node_pc], self.indices[successor_pc])

        # If node_pc is a root node, pop the stack and generate an SCC
        if self.low_link[node_pc] == self.indices[node_pc]:
            scc = []
            while True:
                node = self.stack.pop()
                self.on_stack.remove(node)
                scc.append(node)
                if node == node_pc:
                    break
            self.sccs.append(scc)


def parse_trace_data(filepath):
    """
    Parses a CSV trace file into a list of structured instructions.
    This version is more robust and handles malformed lines.
    """
    instructions = []
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                parts = [p.strip() for p in line.split(';')]
                
                # A valid line must have at least 4 parts.
                if len(parts) < 4:
                    print(f"Warning: Skipping malformed line #{line_num}: '{line}'")
                    continue

                try:
                    instruction = {
                        'seq': int(parts[0]),
                        'type': parts[1],
                        'pc': int(parts[2], 16),
                        'target_pc': int(parts[3], 16)
                    }
                    if instruction['type'] == 'conditional branch':
                        # Conditional branches need a 5th part.
                        if len(parts) < 5:
                            print(f"Warning: Skipping malformed conditional branch on line #{line_num}: '{line}'")
                            continue
                        instruction['taken'] = int(parts[4])
                    instructions.append(instruction)
                except (ValueError, IndexError) as e:
                    # Catch errors from int() conversion or if a part is missing.
                    print(f"Warning: Skipping malformed line #{line_num}: '{line}'. Reason: {e}")
                    continue
                    
    except FileNotFoundError:
        print(f"Error: The file '{filepath}' was not found.")
        return None
    except Exception as e:
        print(f"An error occurred while parsing the file: {e}")
        return None
        
    return instructions

def build_cfg_from_instructions(instructions):
    """
    Builds a Control Flow Graph from a list of parsed instructions.
    This version correctly handles dynamic traces by first creating a static
    representation of the code, then building blocks in PC order.
    """
    cfg = CFG()
    if not instructions:
        return cfg

    # Create a static, unique mapping of PC to instruction.
    # This is crucial because a dynamic trace may execute the same instruction multiple times.
    # We sort by PC to process the code in its static layout order.
    unique_instructions = {instr['pc']: instr for instr in instructions}
    sorted_pcs = sorted(unique_instructions.keys())

    # --- 1. Identify Leaders ---
    # A leader is the first instruction of a basic block.
    leaders = set()
    if sorted_pcs:
        # The very first instruction is a leader.
        leaders.add(sorted_pcs[0])

    for pc in sorted_pcs:
        instr = unique_instructions[pc]
        # Any instruction that is the target of a branch is a leader.
        if 'branch' in instr['type']:
            target_pc = instr.get('target_pc')
            if target_pc in unique_instructions:
                leaders.add(target_pc)
            
            # The instruction immediately following a branch is also a leader.
            # Find the instruction that would normally execute next.
            current_pc_index = sorted_pcs.index(pc)
            if current_pc_index + 1 < len(sorted_pcs):
                fallthrough_pc = sorted_pcs[current_pc_index + 1]
                leaders.add(fallthrough_pc)

    # --- 2. Create and Populate Basic Blocks ---
    sorted_leaders = sorted(list(leaders))
    leader_map = {leader: i for i, leader in enumerate(sorted_leaders)}

    for i, leader_pc in enumerate(sorted_leaders):
        block = BasicBlock(leader_pc)
        
        # Determine the end of the block. It ends right before the next leader.
        next_leader_pc = None
        if i + 1 < len(sorted_leaders):
            next_leader_pc = sorted_leaders[i+1]

        # Add all instructions from the current leader up to the next leader.
        current_pc_index = sorted_pcs.index(leader_pc)
        for j in range(current_pc_index, len(sorted_pcs)):
            instr_pc = sorted_pcs[j]
            if next_leader_pc and instr_pc >= next_leader_pc:
                break
            block.instructions.append(unique_instructions[instr_pc])
        
        if block.instructions:
            block.end_pc = block.instructions[-1]['pc']
        
        cfg.add_block(block)

    # --- 3. Connect Successors ---
    for block in cfg.blocks.values():
        if not block.instructions:
            continue
        
        last_instr = block.instructions[-1]
        
        # Find the PC of the instruction that would execute next if no branch is taken.
        current_pc_index = sorted_pcs.index(last_instr['pc'])
        fallthrough_pc = None
        if current_pc_index + 1 < len(sorted_pcs):
            fallthrough_pc = sorted_pcs[current_pc_index + 1]

        if last_instr['type'] == 'regular':
            if fallthrough_pc in cfg.blocks:
                block.successors.append(fallthrough_pc)
        
        elif last_instr['type'] == 'branch': # Unconditional
            target_pc = last_instr.get('target_pc')
            if target_pc in cfg.blocks:
                block.successors.append(target_pc)

        elif last_instr['type'] == 'conditional branch':
            # Add the branch target
            target_pc = last_instr.get('target_pc')
            if target_pc in cfg.blocks:
                block.successors.append(target_pc)
            
            # Add the fall-through path
            if fallthrough_pc in cfg.blocks and fallthrough_pc not in block.successors:
                block.successors.append(fallthrough_pc)

    return cfg

def write_cfg_to_dot(cfg, filepath):
    """Writes the CFG to a .dot file for visualization."""
    with open(filepath, 'w') as f:
        f.write("digraph CFG {\n")
        f.write('    node [shape=box, fontname="Courier New"];\n')
        for pc, block in cfg.blocks.items():
            label = f"start: {hex(block.start_pc)}\nend: {hex(block.end_pc) if block.end_pc else 'N/A'}"
            f.write(f'    "{hex(pc)}" [label="{label}"];\n')
            for successor_pc in block.successors:
                f.write(f'    "{hex(pc)}" -> "{hex(successor_pc)}";\n')
        f.write("}\n")

def encode_cfg_path(cfg, trace_pcs):
    """
    Encodes the path taken through the CFG as a sequence of 0s and 1s.
    This function traverses the CFG block by block, using the trace_pcs list
    only to resolve conditional branches.
    """
    if not trace_pcs or not cfg.blocks:
        return []

    # Create a map from any PC to the starting PC of its containing block.
    pc_to_block_start = {
        instr['pc']: block.start_pc
        for block in cfg.blocks.values()
        for instr in block.instructions
    }

    path_bits = []
    trace_idx = -1
    current_block_pc = None

    # 1. Find the first PC in the trace that exists in our CFG to start traversal.
    for i, pc in enumerate(trace_pcs):
        if pc in pc_to_block_start:
            trace_idx = i
            current_block_pc = pc_to_block_start[pc]
            break
    
    if current_block_pc is None:
        print("Could not find a starting point in the trace that maps to the CFG.")
        return []

    print (f"Starting CFG traversal from block at PC {hex(current_block_pc)} and trace idx {trace_idx}")
    print (f"The total number of instructions to go through is {len(trace_pcs)}")
    
    # 2. Traverse the CFG, using the trace to guide decisions.
    while trace_idx < len(trace_pcs):
        block = cfg.blocks.get(current_block_pc)
        if not block:
            break

        # If the block is a conditional branch, decide which way to go.
        if len(block.successors) == 2:
            succ0, succ1 = block.successors
            
            # Look ahead in the trace to find the next block that was executed.
            next_block_in_trace = None
            for i in range(trace_idx + 1, len(trace_pcs)):
                next_pc_in_trace = trace_pcs[i]
                if next_pc_in_trace in pc_to_block_start:
                    next_block_in_trace = pc_to_block_start[next_pc_in_trace]
                    # Check if this next block is one of our successors.
                    if next_block_in_trace == succ0 or next_block_in_trace == succ1:
                        trace_idx = i # Update trace index, skipping intermediate PCs.
                        break
            
            if next_block_in_trace == succ1:
                path_bits.append(1)
                current_block_pc = succ1
            elif next_block_in_trace == succ0:
                path_bits.append(0)
                current_block_pc = succ0
            else:
                # Could not determine path from the rest of the trace.
                break
        
        # If the block has one successor, just follow it.
        elif len(block.successors) == 1:
            current_block_pc = block.successors[0]
            # We still need to advance the trace index to the start of the next block.
            found_next_block = False
            for i in range(trace_idx + 1, len(trace_pcs)):
                next_pc_in_trace = trace_pcs[i]
                if next_pc_in_trace in pc_to_block_start and pc_to_block_start[next_pc_in_trace] == current_block_pc:
                    trace_idx = i
                    found_next_block = True
                    break
            if not found_next_block:
                break # End of trace or path diverged.
        
        # If the block has no successors, traversal ends.
        else:
            break
            
    print (f"Generated {len(path_bits)} path bits")
    return path_bits

def encode_iterations(cfg, trace_pcs, loop_blocks_set):
    """
    Traverses the CFG guided by the trace and encodes branch outcomes for a *specific loop*.
    An iteration is a sequence of branch outcomes that occurs within the basic blocks
    defined in `loop_blocks_set`.
    """
    if not trace_pcs or not cfg.blocks or not loop_blocks_set:
        return []

    pc_to_block_start = {
        instr['pc']: block.start_pc
        for block in cfg.blocks.values()
        for instr in block.instructions
    }

    all_iterations = []
    current_iteration_bits = []
    visited_blocks_in_iteration = set()
    
    trace_idx = -1
    current_block_pc = None

    # Find the first valid starting block from the trace
    for i, pc in enumerate(trace_pcs):
        if pc in pc_to_block_start:
            trace_idx = i
            current_block_pc = pc_to_block_start[pc]
            break
    
    if current_block_pc is None:
        return []

    # Traverse the CFG
    while trace_idx < len(trace_pcs):
        # Only process blocks that are part of the target loop
        if current_block_pc not in loop_blocks_set:
            # Scan forward in the trace until we re-enter the loop
            found_next_loop_block = False
            for i in range(trace_idx + 1, len(trace_pcs)):
                pc = trace_pcs[i]
                if pc in pc_to_block_start:
                    b_pc = pc_to_block_start[pc]
                    if b_pc in loop_blocks_set:
                        trace_idx = i
                        current_block_pc = b_pc
                        found_next_loop_block = True
                        break
            if not found_next_loop_block:
                break # Reached end of trace without re-entering the loop
            continue

        # Check if we've cycled back, indicating a new iteration
        if current_block_pc in visited_blocks_in_iteration:
            if current_iteration_bits:
                all_iterations.append(current_iteration_bits)
            current_iteration_bits = []
            visited_blocks_in_iteration.clear()

        visited_blocks_in_iteration.add(current_block_pc)
        
        block = cfg.blocks.get(current_block_pc)
        if not block:
            break

        next_block_pc = None
        if len(block.successors) == 2:
            succ0, succ1 = block.successors
            
            next_block_in_trace = None
            next_trace_idx = -1
            for i in range(trace_idx + 1, len(trace_pcs)):
                pc = trace_pcs[i]
                if pc in pc_to_block_start:
                    b_pc = pc_to_block_start[pc]
                    if b_pc == succ0 or b_pc == succ1:
                        next_block_in_trace = b_pc
                        next_trace_idx = i
                        break
            
            is_cycle_branch = next_block_in_trace in visited_blocks_in_iteration

            if next_block_in_trace == succ1:
                if not is_cycle_branch:
                    current_iteration_bits.append(1)
                next_block_pc = succ1
            elif next_block_in_trace == succ0:
                if not is_cycle_branch:
                    current_iteration_bits.append(0)
                next_block_pc = succ0
            
            if next_block_in_trace:
                trace_idx = next_trace_idx
            else:
                break

        elif len(block.successors) == 1:
            next_block_pc = block.successors[0]
            found_next = False
            for i in range(trace_idx + 1, len(trace_pcs)):
                pc = trace_pcs[i]
                if pc in pc_to_block_start and pc_to_block_start[pc] == next_block_pc:
                    trace_idx = i
                    found_next = True
                    break
            if not found_next:
                break
        else:
            break

        current_block_pc = next_block_pc
        if current_block_pc is None:
            break

    if current_iteration_bits:
        all_iterations.append(current_iteration_bits)
        
    return all_iterations

def write_encoded_iterations_to_file(iterations, filename, input_datafile):
    """
    Converts each list of branch outcomes (e.g., [0, 0, 1, 0]) into an 
    integer (e.g., 2) and writes the numbers to a text file, one per line,
    inside a directory named after the input datafile.
    """
    try:
        # Create a directory name from the input file (e.g., "/path/to/trace.csv" -> "trace")
        base_name = os.path.basename(input_datafile)
        dir_name = os.path.splitext(base_name)[0]
        os.makedirs(dir_name, exist_ok=True)
        
        # Construct the full path for the output file
        filepath = os.path.join(dir_name, filename)

        with open(filepath, 'w') as f:
            for bit_list in iterations:
                if not bit_list:
                    continue
                # Join the list of bits into a string, e.g., [0, 0, 1, 0] -> "0010"
                binary_string = "".join(map(str, bit_list))
                # Convert the binary string to its integer value
                number = int(binary_string, 2)
                f.write(f"{number}\n")
        print(f"\n[+] Encoded iterations successfully written to {filepath}")
    except IOError as e:
        print(f"\n[-] Error writing to file {filepath}: {e}")
        return
    
def main():

    parser = argparse.ArgumentParser(description="Analyze a trace file and extract loop iterations.")
    parser.add_argument("input_file", help="Path to the trace CSV file to analyze")
    args = parser.parse_args()

    file_to_analyze = args.input_file

    print(f"--- Analyzing Trace from File: '{file_to_analyze}' ---")
    instructions = parse_trace_data(file_to_analyze)
    if not instructions:
        print("No instructions parsed. Exiting.")
        return

    trace_pcs = [instr['pc'] for instr in instructions]
    cfg = build_cfg_from_instructions(instructions)

    dot_filepath = "cfg.dot"
    write_cfg_to_dot(cfg, dot_filepath)
    print(f"\n[+] CFG written to {dot_filepath}")

    print("\n[1] Constructed Basic Blocks:")
    for pc, block in sorted(cfg.blocks.items()):
        print(f"  - {block}")
        print(f"    Successors: {[hex(s) for s in block.successors]}")

    loops = cfg.find_loops()

    print("\n[2] Detected Loops:")
    if loops:
        for i, loop in enumerate(loops):
            print(f"  Loop #{i+1}:")
            hex_loop = [hex(pc) for pc in loop]
            print(f"    Basic Blocks (by start_pc): {' -> '.join(hex_loop)}")
    else:
        print("  No loops were detected in the provided trace.")

    print("\n[3] Encoding Iterations for Each Loop:")
    if loops:
        for i, loop_blocks in enumerate(loops):
            loop_blocks_set = set(loop_blocks)
            iterations = encode_iterations(cfg, trace_pcs, loop_blocks_set)
            
            print(f"\n--- Loop #{i+1} ---")
            print(f"  Found {len(iterations)} iterations.")
            # Print the first 5 iterations as a sample
            for j, iter_bits in enumerate(iterations[:5]):
                print(f"    Iteration {j+1}: {iter_bits}")
            if len(iterations) > 5:
                print(f"    ... and {len(iterations) - 5} more iterations.")

            # Write the integer representation of the iterations to a file
            output_filename = f"loop_{i+1}_iterations.txt"
            write_encoded_iterations_to_file(iterations, output_filename, file_to_analyze)
    else:
        print("  No loops were detected in the provided trace.")

if __name__ == '__main__':
    main()
