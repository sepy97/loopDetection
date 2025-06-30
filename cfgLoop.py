import re

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

if __name__ == "__main__":
    # Smaller datafile for testing purposes
    #branches = parse_branch_file('/sputnik/toIntel/loopDetection/fp_test.txt')
    # Larger datafile for real data collection
    branches = parse_branch_file('/sputnik/toIntel/cbp2025/trace_files/media_1_traces.txt')

    cfg_loops = analyze_loop_structure(branches)

    print(f"Detected {len(cfg_loops)} loops using control flow analysis.")
    for loop in cfg_loops:
        print(f"Loop: Head={loop['loop_head']}, Iterations={loop['iterations']}, "
              f"Cycles={loop['start_cycle']}-{loop['end_cycle']}, "
              f"Nesting={loop['nested_level']}, Body size={len(loop['loop_body_pcs'])}")
        # print iterations for each loop in a separate file
        with open(f"loop_{loop['loop_head']}_iterations.txt", 'w') as f:
            for pc in loop['loop_body_pcs']:
                f.write(f"{pc}\n")



