import re
from collections import defaultdict


def normalize_addr(addr):
    return int(addr, 16) if isinstance(addr, str) else addr


def detect_loops(trace):
    loop_candidates = defaultdict(list)  # { (loop_head, loop_back): [start_indices] }
    
    for i, entry in enumerate(trace):
        pc = normalize_addr(entry['pc'])
        target = normalize_addr(entry['next_pc']) if 'next_pc' in entry else None

        # Backward taken branch implies a possible loop
        if entry['direction'] == 1 and target is not None and target < pc:
            loop_head = target
            loop_back = pc
            loop_candidates[(loop_head, loop_back)].append(i)

    detected_loops = []

    for (head, back), indices in loop_candidates.items():
        for idx in indices:
            # Walk back from the taken branch to find all entries between head and back
            loop_body = []
            for j in range(idx, -1, -1):
                pc_j = normalize_addr(trace[j]['pc'])
                if pc_j == head:
                    loop_body = trace[j:idx+1]
                    break
            if loop_body:
                detected_loops.append({
                    'loop_head': head,
                    'loop_back': back,
                    'start_index': idx - len(loop_body) + 1,
                    'end_index': idx,
                    'body': loop_body
                })

    return detected_loops

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

def detect_loops(branches, min_iterations=2):
    """
    Scan the sequence of branch records and find *all* repeated,
    non-overlapping substrings (loops) of length >= 1 that repeat
    at least `min_iterations` times.

    Each detected loop is reported as a dict:
      {
        'header_index': first index in `branches` where the loop begins,
        'length':       number of branches in the loop body,
        'iterations':   how many consecutive repetitions were seen
      }
    """
    # 1) Encode each branch as a single integer
    #    Here we shift the PC (hex string) left 1 bit and OR in the taken-bit (0/1).
    vals = [
        (int(b['pc'], 16) << 1) | b['direction']
        for b in branches
    ]
    N = len(vals)
    if N < 2:
        return []

    # 2) Parameters for 64-bit rolling hash
    MOD = 1 << 64
    BASE = 1315423911  # a large odd constant

    loops = []

    # We only need to check loop bodies up to length N//2
    max_L = N // 2

    for L in range(1, max_L + 1):
        # 2a) Compute hash of the first window [0..L-1]
        h = 0
        for i in range(L):
            h = (h * BASE + vals[i]) & MOD

        # Store { hash_value: [start_indices...] }
        hash_map = {h: [0]}

        # Precompute BASE^L mod 2^64 for fast “drop” in rolling hash
        power_L = pow(BASE, L, MOD)

        # 2b) Slide window from 1..(N-L)
        for start in range(1, N - L + 1):
            # roll: remove vals[start-1], add vals[start+L-1]
            h = (
                (h * BASE
                 - (vals[start - 1] * power_L)  # drop oldest
                 + vals[start + L - 1]          # add newest
                ) & MOD
            )
            hash_map.setdefault(h, []).append(start)

        # 2c) Look for *consecutive* repeats: i, i+L, i+2L, …
        for idx_list in hash_map.values():
            idx_set = set(idx_list)
            for i in idx_list:
                # count how many back-to-back repetitions we see
                count = 1
                while (i + count * L) in idx_set:
                    count += 1
                if count >= min_iterations:
                    loops.append({
                        'header_index': i,
                        'length':       L,
                        'iterations':   count
                    })

    return loops

def detect_loops_fast(branches, min_iters=2):
    """
    O(N log N) loop‐finder via rolling‐hash + per‐index binary search.
    Returns a list of (start_index, length, iterations).
    """
    # 1) encode each branch as an integer
    vals = [(int(b['pc'], 16) << 1) | b['direction'] for b in branches]
    N = len(vals)
    if N < 2:
        return []

    # 2) build rolling hash: H[i] = hash(vals[0:i])
    MOD = (1<<61) - 1   # use a fast Mersenne-style mod
    BASE = 1315423911

    H = [0] * (N+1)
    P = [1] * (N+1)
    for i in range(N):
        H[i+1] = (H[i]*BASE + vals[i]) % MOD
        P[i+1] = (P[i]*BASE)    % MOD

    def get_hash(l, r):
        """Hash of vals[l:r] in O(1)."""
        x = H[r] - (H[l] * P[r-l] % MOD)
        return x + MOD if x < 0 else x

    loops = []
    # 3) for each possible start i
    for i in range(N):
        max_L = (N - i) // 2
        if max_L < 1:
            break

        # binary search for the largest L with trace[i:i+L] == trace[i+L:i+2L]
        lo, hi, best = 1, max_L, 0
        while lo <= hi:
            mid = (lo + hi) // 2
            if get_hash(i,   i+mid) == get_hash(i+mid, i+2*mid):
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1

        # if we found a repetition of length best, count how many times it repeats
        if best > 0:
            count = 1
            while i + (count+1)*best <= N and \
                  get_hash(i, i+best) == get_hash(i+count*best, i+(count+1)*best):
                count += 1

            if count >= min_iters:
                loops.append((i, best, count))

    return loops



if __name__ == "__main__":
    # Smaller datafile for testing
    branches = parse_branch_file('/sputnik/toIntel/loopDetection/fp_test.txt')
    # Large datafile for measurements:
    #branches = parse_branch_file('/sputnik/toIntel/cbp2025/trace_files/media_0_traces.txt')
    loops = detect_loops_fast(branches, min_iters=2)
    print(f"Found {len(loops)} loops in the trace.")
    for (i, L, it) in loops:
        if L > 100:
            print(f"Loop at index {i}, body length {L}, repeats {it}×")

