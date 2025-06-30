import re
import csv
from collections import defaultdict, deque
import time


def analyze_loop_structure(branches):
    """
    Alternative approach: Analyze loop structure using control flow analysis.
    This function focuses on finding natural loops using dominance analysis.
    """
    loops = []
    
    # Build control flow graph
    cfg = {}
    for i, branch in enumerate(branches):
        pc = branch['pc']
        if pc not in cfg:
            cfg[pc] = {'predecessors': set(), 'successors': set(), 'indices': []}
        cfg[pc]['indices'].append(i)
    
    # Connect predecessors and successors based on execution order
    for i in range(len(branches) - 1):
        current_pc = branches[i]['pc']
        next_pc = branches[i + 1]['pc']
        
        if current_pc in cfg and next_pc in cfg:
            cfg[current_pc]['successors'].add(next_pc)
            cfg[next_pc]['predecessors'].add(current_pc)
    
    # Find back edges (edges that go to a dominating node)
    back_edges = []
    for pc in cfg:
        for successor in cfg[pc]['successors']:
            # Simple heuristic: if successor appears earlier in execution, it's likely a back edge
            if cfg[successor]['indices'][0] < cfg[pc]['indices'][0]:
                back_edges.append((pc, successor))
    
    # For each back edge, find the natural loop
    for tail_pc, head_pc in back_edges:
        # Find all nodes in the loop by doing backward traversal from tail to head
        loop_nodes = {head_pc, tail_pc}
        stack = [tail_pc]
        
        while stack:
            current = stack.pop()
            for pred in cfg[current]['predecessors']:
                if pred not in loop_nodes:
                    loop_nodes.add(pred)
                    stack.append(pred)
                    if len(loop_nodes) > 100:  # Prevent infinite loops in analysis
                        break
        
        # Calculate loop statistics
        all_indices = []
        for node in loop_nodes:
            all_indices.extend(cfg[node]['indices'])
        
        if all_indices:
            all_indices.sort()
            start_cycle = branches[all_indices[0]]['cycle']
            end_cycle = branches[all_indices[-1]]['cycle']
            
            # Estimate iterations by counting how many times head is executed
            head_executions = len(cfg[head_pc]['indices'])
            
            loops.append({
                'loop_head': head_pc,
                'loop_tail': tail_pc,
                'iterations': head_executions,
                'start_cycle': start_cycle,
                'end_cycle': end_cycle,
                'loop_body_pcs': loop_nodes,
                'nested_level': 0
            })
    
    # Calculate nesting levels
    for i, loop in enumerate(loops):
        nesting_level = 0
        for other_loop in loops:
            if (other_loop != loop and 
                other_loop['start_cycle'] <= loop['start_cycle'] and 
                other_loop['end_cycle'] >= loop['end_cycle'] and
                len(other_loop['loop_body_pcs']) > len(loop['loop_body_pcs'])):
                nesting_level += 1
        loop['nested_level'] = nesting_level
    
    return loops

def parse_branch_file(filename):
    """Parse the branch instruction file and return a list of branch records."""
    branches = []
    with open(filename, 'r') as f:
        print(f"Parsing branch file: {filename}")
        for line in f:
            # Check if this is a branch instruction
            if 'seq_no:' in line and 'pc:' in line and 'commit cycle' in line:
                # Determine if it's conditional by checking for resolve_dir
                is_conditional = 'resolve_dir:' in line

                if is_conditional:
                    # Extract information for conditional branches (without next_pc)
                    match = re.search(r'seq_no:(\d+).*pc:(0x[0-9a-fA-F]+).*commit cycle (\d+).*resolve_dir:(\d+)', line)
                    if match:
                        seq_no = int(match.group(1))
                        pc = match.group(2)
                        cycle = int(match.group(3))
                        direction = int(match.group(4))
                        branches.append({
                            'type': 'conditional',
                            'seq_no': seq_no,
                            'pc': pc,
                            'cycle': cycle,
                            'direction': direction
                        })
                else:
                    # Extract information for unconditional branches (without next_pc)
                    match = re.search(r'seq_no:?\s*(\d+).*pc:?\s*(0x[0-9a-fA-F]+).*commit cycle (\d+)', line)
                    if match:
                        seq_no = int(match.group(1))
                        pc = match.group(2)
                        cycle = int(match.group(3))
                        branches.append({
                            'type': 'unconditional',
                            'seq_no': seq_no,
                            'pc': pc,
                            'cycle': cycle,
                            'direction': 1  # Always taken for unconditional branches
                        })

    print(f"Parsed {len(branches)} branch records from {filename}.")
    return branches


class BasicBlock:
    def __init__(self, start_pc, start_seq):
        self.start_pc = start_pc
        self.end_pc = None
        self.start_seq = start_seq
        self.end_seq = None
        self.instructions = []
        self.successors = set()
        self.predecessors = set()
        
    def add_instruction(self, seq, pc, target_pc=None):
        self.instructions.append((seq, pc, target_pc))
        self.end_pc = pc
        self.end_seq = seq
        
    def __repr__(self):
        return f"BB[{self.start_pc}-{self.end_pc}]({len(self.instructions)} instrs)"

class CFG:
    def __init__(self):
        self.basic_blocks = {}  # pc -> BasicBlock
        self.pc_to_block = {}   # pc -> BasicBlock (for any PC in block)
        
    def add_basic_block(self, bb):
        self.basic_blocks[bb.start_pc] = bb
        for seq, pc, _ in bb.instructions:
            self.pc_to_block[pc] = bb
            
    def add_edge(self, from_pc, to_pc):
        from_bb = self.basic_blocks.get(from_pc)
        to_bb = self.basic_blocks.get(to_pc)
        if from_bb and to_bb:
            from_bb.successors.add(to_bb)
            to_bb.predecessors.add(from_bb)
            
    def get_block_by_pc(self, pc):
        return self.pc_to_block.get(pc)

def parse_instruction_trace(filename):
    """Parse the complete instruction trace CSV file."""
    instructions = []
    
    with open(filename, 'r') as f:
        reader = csv.reader(f, delimiter=';')
        for row in reader:
            if len(row) < 3:
                continue
                
            seq = int(row[0].strip())
            instr_type = row[1].strip()
            pc = row[2].strip()
            target_pc = row[3].strip() if len(row) > 3 else None
            taken = None
            
            if len(row) > 4 and row[4].strip():
                taken = int(row[4].strip())
                
            instructions.append({
                'seq': seq,
                'type': instr_type,
                'pc': pc,
                'target_pc': target_pc,
                'taken': taken
            })
    
    print(f"Parsed {len(instructions)} instructions from {filename}")
    return instructions

def build_cfg(instructions):
    """Build Control Flow Graph from instruction trace."""
    print("Building CFG...")
    
    # Step 1: Identify basic block leaders (start points)
    leaders = set()
    leaders.add(instructions[0]['pc'])  # First instruction is always a leader
    
    for i, instr in enumerate(instructions):
        # Branch/jump targets are leaders
        if instr['type'] in ['branch', 'conditional branch'] and instr['target_pc']:
            leaders.add(instr['target_pc'])
            
        # Instructions after branches are leaders
        if i + 1 < len(instructions):
            if instr['type'] in ['branch', 'conditional branch']:
                leaders.add(instructions[i + 1]['pc'])
    
    print(f"Found {len(leaders)} basic block leaders")
    
    # Step 2: Build basic blocks
    cfg = CFG()
    current_bb = None
    
    for instr in instructions:
        pc = instr['pc']
        
        # Start new basic block if this PC is a leader
        if pc in leaders:
            if current_bb:
                cfg.add_basic_block(current_bb)
            current_bb = BasicBlock(pc, instr['seq'])
            
        # Add instruction to current basic block
        if current_bb:
            current_bb.add_instruction(instr['seq'], pc, instr.get('target_pc'))
            
        # End basic block at branches
        if instr['type'] in ['branch', 'conditional branch']:
            if current_bb:
                cfg.add_basic_block(current_bb)
                current_bb = None
    
    # Add final basic block if exists
    if current_bb:
        cfg.add_basic_block(current_bb)
    
    print(f"Created {len(cfg.basic_blocks)} basic blocks")
    
    # Step 3: Add edges between basic blocks
    for instr in instructions:
        if instr['type'] == 'branch':
            # Unconditional branch
            from_pc = instr['pc']
            to_pc = instr['target_pc']
            if from_pc in cfg.basic_blocks and to_pc in cfg.basic_blocks:
                cfg.add_edge(from_pc, to_pc)
                
        elif instr['type'] == 'conditional branch':
            from_pc = instr['pc']
            
            # Add edge for taken branch
            if instr['taken'] == 1 and instr['target_pc']:
                to_pc = instr['target_pc']
                if to_pc in cfg.basic_blocks:
                    cfg.add_edge(from_pc, to_pc)
            
            # Add edge for fall-through (not taken or always fall-through)
            # Find next instruction after this branch
            current_seq = instr['seq']
            for next_instr in instructions:
                if next_instr['seq'] == current_seq + 1:
                    to_pc = next_instr['pc']
                    if to_pc in cfg.basic_blocks:
                        cfg.add_edge(from_pc, to_pc)
                    break
        
        elif instr['type'] == 'regular':
            # Regular instructions: add fall-through edge at block boundaries
            current_seq = instr['seq']
            from_bb = cfg.get_block_by_pc(instr['pc'])
            
            if from_bb and instr['seq'] == from_bb.end_seq:
                # This is the last instruction in a basic block
                for next_instr in instructions:
                    if next_instr['seq'] == current_seq + 1:
                        to_pc = next_instr['pc']
                        to_bb = cfg.basic_blocks.get(to_pc)
                        if to_bb:
                            cfg.add_edge(from_bb.start_pc, to_pc)
                        break
    
    print("CFG construction complete")
    return cfg

def find_back_edges_and_loops(cfg):
    """Find back edges using DFS and detect natural loops."""
    print("Finding loops using back-edge detection...")
    
    visited = set()
    rec_stack = set()
    back_edges = []
    
    def dfs(bb):
        visited.add(bb)
        rec_stack.add(bb)
        
        for successor in bb.successors:
            if successor not in visited:
                dfs(successor)
            elif successor in rec_stack:
                # Back edge found: bb -> successor
                back_edges.append((bb, successor))
        
        rec_stack.remove(bb)
    
    # Start DFS from all entry points (blocks with no predecessors)
    entry_blocks = [bb for bb in cfg.basic_blocks.values() if not bb.predecessors]
    if not entry_blocks:
        # If no clear entry, start from first block
        entry_blocks = [list(cfg.basic_blocks.values())[0]]
    
    for entry in entry_blocks:
        if entry not in visited:
            dfs(entry)
    
    print(f"Found {len(back_edges)} back edges")
    
    # For each back edge, find the natural loop
    loops = []
    for tail_bb, head_bb in back_edges:
        loop_blocks = find_natural_loop(tail_bb, head_bb)
        
        # Calculate loop statistics
        total_instructions = sum(len(bb.instructions) for bb in loop_blocks)
        loop_pcs = set()
        min_seq = float('inf')
        max_seq = 0
        
        for bb in loop_blocks:
            for seq, pc, _ in bb.instructions:
                loop_pcs.add(pc)
                min_seq = min(min_seq, seq)
                max_seq = max(max_seq, seq)
        
        # Count iterations by analyzing how many times head block is executed
        head_executions = count_block_executions(head_bb, cfg)
        
        loops.append({
            'head_pc': head_bb.start_pc,
            'tail_pc': tail_bb.start_pc,
            'head_block': head_bb,
            'tail_block': tail_bb,
            'loop_blocks': loop_blocks,
            'loop_pcs': loop_pcs,
            'total_instructions': total_instructions,
            'estimated_iterations': head_executions,
            'sequence_range': (min_seq, max_seq)
        })
    
    return loops

def find_natural_loop(tail_bb, head_bb):
    """Find all blocks in the natural loop defined by back edge tail->head."""
    loop_blocks = {head_bb}
    
    if tail_bb != head_bb:
        loop_blocks.add(tail_bb)
        stack = [tail_bb]
        
        while stack:
            current = stack.pop()
            for pred in current.predecessors:
                if pred not in loop_blocks:
                    loop_blocks.add(pred)
                    stack.append(pred)
    
    return loop_blocks

def count_block_executions(block, cfg):
    """Estimate how many times a block was executed by counting its instructions."""
    return len(block.instructions)

def detect_nested_loops(loops):
    """Determine nesting relationships between loops."""
    for i, loop1 in enumerate(loops):
        nesting_level = 0
        for j, loop2 in enumerate(loops):
            if i != j:
                # Check if loop1 is nested inside loop2
                if (loop1['head_block'] in loop2['loop_blocks'] and 
                    loop1['sequence_range'][0] >= loop2['sequence_range'][0] and
                    loop1['sequence_range'][1] <= loop2['sequence_range'][1]):
                    nesting_level += 1
        loop1['nesting_level'] = nesting_level

def analyze_loops_from_trace(filename):
    """Main function to analyze loops from instruction trace."""
    start_time = time.time()

    # Parse instruction trace
    instructions = parse_instruction_trace(filename)
    parse_time = time.time()

    # Build CFG
    cfg = build_cfg(instructions)
    cfg_time = time.time()

    # Find loops
    loops = find_back_edges_and_loops(cfg)
    loop_time = time.time()

    # Analyze nesting
    detect_nested_loops(loops)
    nest_time = time.time()

    # Print results
    print(f"\n{'='*60}")
    print(f"LOOP ANALYSIS RESULTS")
    print(f"{'='*60}")
    print(f"Total instructions: {len(instructions):,}")
    print(f"Total basic blocks: {len(cfg.basic_blocks):,}")
    print(f"Loops detected: {len(loops)}")
    print(f"\nTiming:")
    print(f"  Parse time: {parse_time - start_time:.2f}s")
    print(f"  CFG build time: {cfg_time - parse_time:.2f}s")
    print(f"  Loop detection: {loop_time - cfg_time:.2f}s")
    print(f"  Nesting analysis: {nest_time - loop_time:.2f}s")
    print(f"  Total time: {nest_time - start_time:.2f}s")

    print(f"\n{'Loop Details:':<15}")
    print(f"{'ID':<3} {'Head PC':<12} {'Tail PC':<12} {'Blocks':<7} {'Instrs':<7} {'Est.Iter':<8} {'Nesting':<7}")
    print("-" * 70)

    for i, loop in enumerate(loops):
        print(f"{i+1:<3} {loop['head_pc']:<12} {loop['tail_pc']:<12} "
                f"{len(loop['loop_blocks']):<7} {loop['total_instructions']:<7} "
                f"{loop['estimated_iterations']:<8} {loop['nesting_level']:<7}")

    return loops, cfg


if __name__ == "__main__":
    # Smaller datafile for testing purposes
    #branches = parse_branch_file('/sputnik/toIntel/loopDetection/fp_test.txt')
    # Larger datafile for real data collection
    #branches = parse_branch_file('/sputnik/toIntel/cbp2025/trace_files/media_1_traces.txt')

    #cfg_loops = analyze_loop_structure(branches)

    #print(f"Detected {len(cfg_loops)} loops using control flow analysis.")
    #for loop in cfg_loops:
    #    print(f"Loop: Head={loop['loop_head']}, Iterations={loop['iterations']}, "
    #          f"Cycles={loop['start_cycle']}-{loop['end_cycle']}, "
    #          f"Nesting={loop['nested_level']}, Body size={len(loop['loop_body_pcs'])}")
    #    # print iterations for each loop in a separate file
    #    with open(f"loop_{loop['loop_head']}_iterations.txt", 'w') as f:
    #        for pc in loop['loop_body_pcs']:
    #            f.write(f"{pc}\n")

    loops, cfg = analyze_loops_from_trace("/sputnik/toIntel/cbp2025/fp_full.csv")
    
    # Print detailed information for first few loops
    print(f"\nDetailed Loop Information:")
    for i, loop in enumerate(loops[:3]):  # Show first 3 loops
        print(f"\nLoop {i+1}:")
        print(f"  Head: {loop['head_pc']} -> Tail: {loop['tail_pc']}")
        print(f"  Blocks in loop: {len(loop['loop_blocks'])}")
        print(f"  Total instructions: {loop['total_instructions']}")
        print(f"  Sequence range: {loop['sequence_range'][0]} - {loop['sequence_range'][1]}")
        print(f"  Estimated iterations: {loop['estimated_iterations']}")
        print(f"  Nesting level: {loop['nesting_level']}")
        print(f"  Loop blocks: {[bb.start_pc for bb in loop['loop_blocks']]}")


