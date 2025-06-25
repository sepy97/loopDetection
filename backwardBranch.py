import re
from collections import Counter
import cycleFinder
from concurrent.futures import ProcessPoolExecutor, as_completed

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
                    # Extract information for conditional branches
                    match = re.search(r'seq_no:(\d+).*pc:(0x[0-9a-fA-F]+).*commit cycle (\d+).*resolve_dir:(\d+).*next_pc:?\s*(0x[0-9a-fA-F]+)', line)
                    if match:
                        seq_no = int(match.group(1))
                        pc = match.group(2)
                        cycle = int(match.group(3))
                        direction = int(match.group(4))
                        next_pc = match.group(5)
                        branches.append({
                            'type': 'conditional',
                            'seq_no': seq_no,
                            'pc': pc,
                            'cycle': cycle,
                            'next_pc': next_pc,
                            'direction': direction
                        })
                else:
                    # Extract information for unconditional branches
                    match = re.search(r'seq_no:?\s*(\d+).*pc:?\s*(0x[0-9a-fA-F]+).*commit cycle (\d+).*next_pc:?\s*(0x[0-9a-fA-F]+)', line)
                    if match:
                        seq_no = int(match.group(1))
                        pc = match.group(2)
                        cycle = int(match.group(3))
                        next_pc = match.group(4)
                        branches.append({
                            'type': 'unconditional',
                            'seq_no': seq_no,
                            'pc': pc,
                            'cycle': cycle,
                            'next_pc': next_pc,
                            'direction': 1  # Always taken for unconditional branches
                        })

    print(f"Parsed {len(branches)} branch records from {filename}.")
    return branches

def detect_loops_from_list(trace_list):
    """
    Scan a list of branch entries and detect loops based on backward taken branches.

    Each entry in trace_list is a dict:
        {
            'type': 'conditional' or 'unconditional',
            'seq_no': int,
            'pc': hex string or int,
            'cycle': int,
            'next_pc': hex string or int (for unconditional branches),
            'direction': 1 or 0,  # 1 for taken, 0 for not taken
        }

    A loop is signaled by any taken branch whose TARGET < PC (i.e., a backward jump).
    Loops are now distinguished by the target pc only.
    Each loop has head_pc, tail_pc, and a collection of iterations. For each iteration the executed
    instruction pcs are recorded.
    """
    # Dictionary that tracks the last occurrences of each PC
    last_occurrences = {}
    # key = target pc → { head_pc, tail_pc, iterations, last }
    loops = {}

    for idx, e in enumerate(trace_list):
        pc = int(e['pc'], 0)
        # Update last_occurrences for the current pc
        if pc not in last_occurrences:
            last_occurrences[pc] = []
        last_occurrences[pc].append(idx)

        # Only process taken branches
        if e['direction'] != 1:
            continue

        tgt = e.get('target', e.get('next_pc'))
        if tgt is None:
            continue
        tgt = int(tgt, 0)

        # Detect a backward taken branch
        if tgt < pc:
            key = tgt  # Now distinguishing loops by the target pc only

            if key not in loops:
                loops[key] = {
                    'head_pc': tgt,
                    'tail_pc': pc,
                    'iterations': [],
                    'last': 0
                }
            else:
                # update tail_pc if current pc is higher than previously recorded tail_pc
                if pc > loops[key]['tail_pc']:
                    loops[key]['tail_pc'] = pc

            loop = loops[key]

            # Look up the last occurrence of the target in trace_list starting from loop['last']
            possible_positions = last_occurrences.get(tgt, [])
            head_pos = loop['last']
            for pos in possible_positions:
                if pos >= loop['last']:
                    head_pos = pos
                    break

            # Record iteration capturing only conditional branch records
            iteration_pcs = [int(item['pc'], 0) for item in trace_list[head_pos:idx+1] if item['type'] == 'conditional']
            loop['iterations'].append({
                'pcs': iteration_pcs,
                'start': head_pos,
                'end': idx
            })
            loop['last'] = idx + 1

    # Return as a list of loop records
    return [
        {
            'head_pc': rec['head_pc'],
            'tail_pc': rec['tail_pc'],
            'iterations': rec['iterations']
        }
        for rec in loops.values()
    ]

def annotate_loops_with_cond_outcomes(loops, trace_list):
    """
    Second pass: For each loop, annotate each iteration with the list of PCs and 
    a string representing conditional branch outcomes ('1' for taken, '0' for not taken)
    using the stored slice indices.
    """
    for loop in loops:
        for iteration in loop['iterations']:
            recs = trace_list[iteration['start'] : iteration['end'] + 1]
            iteration['pcs'] = [int(rec['pc'], 0) for rec in recs if rec['type'] == 'conditional']
            iteration['cond_outcomes'] = ''.join('1' if rec['direction'] == 1 else '0'
                                                 for rec in recs if rec['type'] == 'conditional')
            # Optionally remove boundaries:
            del iteration['start']
            del iteration['end']
    return loops

def generate_trace_ids(loop):
    """
    Generate trace IDs from conditional outcomes of each iteration.
    e.g. trace_id for 111 will be 0b111 = 7
    """
    trace_ids = []
    for iteration in loop['iterations']:
        if iteration['cond_outcomes'] == '':
            print(f"Skipping iteration with no conditional outcomes: {iteration}")
            continue
        trace_id = int(iteration['cond_outcomes'], 2)
        trace_ids.append(trace_id)
    return trace_ids

def find_backward_branches(branch_seq):
    """
    Find all unique backward branches in the branch sequence.
    A branch is considered unique based on (pc, target_pc).
    """
    unique = set()
    unique_branches = []
    for entry in branch_seq:
        if entry['direction'] == 1:  # Only consider taken branches
            target_pc = int(entry.get('target', entry.get('next_pc')), 0)
            current_pc = int(entry['pc'], 0)
            if target_pc < current_pc:
                if target_pc not in unique:
                    unique.add(target_pc)
                    unique_branches.append(entry)
    print(f"Found {len(unique_branches)} unique backward branches.")
    return unique_branches

def detect_backward_branches(loop):
    """
    Detect if any iteration in the loop has backward branches
    i.e. next pc is less than the current pc
    """
    for iteration in loop['iterations']:
        pcs = iteration['pcs']
        if not pcs:
            continue
        # Check if pc is greater than next pc
        if len(pcs) < 20:
            continue
        for  i in range(2, len(pcs)-1):
            if pcs[i] < pcs[i-1]:
                return True
    return False

def detect_duplicate_pcs(loop):
    """
    Detect if any iteration in the loop has duplicate PCs.
    """
    for iteration in loop['iterations']:
        pcs = iteration['pcs']
        if not pcs:
            continue
        # Check for duplicates
        pc_counts = Counter(pcs)
        if any(count > 1 for count in pc_counts.values()):
            #print(f"Duplicate PCs found in iteration: {pcs}")
            return True

    return False

def filter_outer_loops(loops): #, branch_seq):
    """
    Filter out outer loops that have no inner loops.
    An outer loop is defined as one that has no backward branches within its iterations.
    """
    filtered_loops = []
    #TODO: parallelize this loop
    for loop in loops:
        # Check if there are any backward branches in the iterations
        #has_inner_loops = detect_backward_branches(loop)
        has_inner_loops = detect_duplicate_pcs(loop)
        print("Processed loop with head_pc:", loop['head_pc'], "tail_pc:", loop['tail_pc'])
        if not has_inner_loops:
            print("Loop has no inner loop")
            filtered_loops.append(loop)
    print(f"Filtered down to {len(filtered_loops)} innermost loops.")
    return filtered_loops

if __name__ == "__main__":
    #branch_seq = parse_branch_file('/sputnik/toIntel/cbp2025/loopDetection/fp_test.txt')
    branch_seq = parse_branch_file('/sputnik/toIntel/cbp2025/trace_files/compress_0_traces.txt')
    print(f"Total branches parsed: {len(branch_seq)}")
    # Find all backward branches
    backward_branches = find_backward_branches(branch_seq)

    loops = detect_loops_from_list(branch_seq)
    print(f"Total loops detected: {len(loops)}")

    loops = annotate_loops_with_cond_outcomes(loops, branch_seq)
    
    loops = filter_outer_loops(loops)#, branch_seq)
    print(f"Detected {len(loops)} innermost loops!")

    for loop in loops:
            output_filename = f"/sputnik/toIntel/cbp2025/loopDetection/loop_head_{loop['head_pc']}_tail_{loop['tail_pc']}.txt"
            with open(output_filename, 'w') as outfile:
                outfile.write(f"Loop detected: Head {loop['head_pc']}, Tail {loop['tail_pc']}\n")
                for idx, iteration in enumerate(loop['iterations'], 1):
                    iteration_str = " -> ".join(hex(pc) for pc in iteration['pcs'])
                    outfile.write(f"Iteration {idx}: {iteration_str} | Cond outcomes: {iteration['cond_outcomes']}\n")
