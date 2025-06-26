import re
from collections import defaultdict

def primitive_period(vals):
    """
    Given a list `vals`, return the smallest p (1 <= p <= len(vals))
    such that vals == vals[0:p] repeated len(vals)//p times.
    If no smaller p exists, returns len(vals).
    """
    n = len(vals)
    for p in range(1, n//2 + 1):
        if n % p != 0:
            continue
        # compare slice chunks of length p
        chunk = vals[0:p]
        if all(vals[i:i+p] == chunk for i in range(0, n, p)):
            return p
    return n

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

def record_loop_iterations(branches, loops):
    """
    Given:
      - branches: list of branch records (as dicts)
      - loops:   list of triples (start_idx, body_length, iterations)
    
    Returns a list of dicts, one per detected loop:
      {
        'start_index': <i>,
        'length':      <L>,
        'iterations':  [  # list of lists of branch-records
           [ branches[i:i+L] ],       # 1st iteration
           [ branches[i+L:i+2L] ],    # 2nd iteration
           …
        ],
        'start_pc': <pc of first instruction in first iteration>,
        'end_pc':   <pc of last instruction in last iteration>
      }
    """
    recorded = []
    for i, L, count in loops:
        iters = []
        for k in range(count):
            slice_start = i + k * L
            slice_end   = slice_start + L
            iters.append(branches[slice_start : slice_end])
        # Determine start_pc and end_pc
        if iters and iters[0] and iters[-1]:
            start_pc = iters[0][0]['pc']
            end_pc = iters[-1][-1]['pc']
        else:
            start_pc = None
            end_pc = None
        recorded.append({
            'start_index': i,
            'length':      L,
            'iterations':  iters,
            'start_pc':    start_pc,
            'end_pc':      end_pc
        })
    return recorded

def record_loop_iterations_primitives(branches, loops):
    """
    Like before, but for each detected (i, L, count):
      1. Extract the first iteration slice of length L.
      2. Compute its primitive period p.
      3. Reslice all iterations into chunks of length p.
    """
    recorded = []
    # pre-encode to speed up period checks
    vals = [(int(b['pc'],16)<<1)|b['direction'] for b in branches]

    for i, L, count in loops:
        # get the raw first-iteration values
        first_vals = vals[i : i+L]
        p = primitive_period(first_vals)

        # now slice out each true iteration
        true_iters = []
        total_iters = (count * L) // p
        for k in range(total_iters):
            start = i + k * p
            end   = start + p
            true_iters.append(branches[start:end])

        recorded.append({
            'start_index':    i,
            'raw_length':     L,
            'primitive_body': p,
            'iterations':     true_iters
        })

    return recorded
def filter_unique_loops(loops_info):
    """
    Deduplicate loops by true index-span overlap.

    loops_info entries must have:
      - 'start_index'
      - 'primitive_body'
      - 'iterations'           # a list of per-iteration branch-record lists
    """
    candidates = []
    for loop in loops_info:
        i      = loop['start_index']
        p      = loop['primitive_body']
        iters  = loop['iterations']
        count  = len(iters)

        # Build covered indices from each iteration slice explicitly
        covered = set()
        for k in range(count):
            base = i + k * p
            covered |= set(range(base, base + p))

        # Signature by first-iteration PC sequence
        sig = tuple(b['pc'] for b in iters[0])

        # Total span = p × count
        span = p * count

        candidates.append({
            'loop':    loop,
            'covered': covered,
            'sig':     sig,
            'span':    span
        })

    # Sort by total span descending
    candidates.sort(key=lambda c: c['span'], reverse=True)

    accepted = []
    occupied = set()

    for cand in candidates:
        if cand['covered'].isdisjoint(occupied):
            accepted.append(cand['loop'])
            occupied |= cand['covered']

    return accepted

def dedupe_by_header_pc(loops_info):
    """
    Given loops_info (with 'iterations' as lists of branch-record lists),
    keep at most one loop per unique header PC (the first PC of the first iteration).
    """
    seen = set()
    unique = []
    for loop in loops_info:
        # grab the first branch of the first iteration
        header_pc = loop['iterations'][0][0]['pc']
        if header_pc not in seen:
            seen.add(header_pc)
            unique.append(loop)
    return unique

def filter_maximal_loops_by_signature(loops_info):
    """
    From loops_info entries (each with 'iterations' list), return only
    the maximal, non‐overlapping loop bodies.

    1) Collapse by signature → pick earliest start_index.
    2) Sort by signature length descending.
    3) For each candidate, drop it if its signature appears inside a
       larger signature (considered circularly).
    """
    # 1) collapse by signature, keep earliest
    best = {}
    for loop in loops_info:
        sig = tuple(b['pc'] for b in loop['iterations'][0])
        if sig not in best or loop['start_index'] < best[sig]['start_index']:
            best[sig] = loop

    # 2) work in descending length
    candidates = sorted(best.values(),
                        key=lambda L: len(L['iterations'][0]),
                        reverse=True)

    maximal = []
    seen_sigs = []  # list of signatures we’ve kept so far
    for loop in candidates:
        sig = tuple(b['pc'] for b in loop['iterations'][0])
        L   = len(sig)
        # build a “circular” version of each kept signature
        # so that any rotation of it will match
        is_sub = False
        for big_sig in seen_sigs:
            # only check bigger signatures
            if len(big_sig) <= L:
                continue
            # circularize: double it
            dbl = big_sig + big_sig
            # look for sig as a contiguous subsequence
            if any(dbl[i:i+L] == sig for i in range(len(big_sig))):
                is_sub = True
                break

        if not is_sub:
            maximal.append(loop)
            seen_sigs.append(sig)

    # sort back by start_index if you like
    maximal.sort(key=lambda L: L['start_index'])
    return maximal

def canonical_rotation(sig):
    """
    Given a tuple `sig` of length p, return the lexicographically
    smallest rotation of it.
    """
    p = len(sig)
    # double the tuple so every rotation is a slice of length p
    doubled = sig + sig
    # examine all p rotations and pick the min
    best = min(tuple(doubled[i:i+p]) for i in range(p))
    return best

def find_unique_loops_circular(branches, min_iters=2):
    """
    Detect loops, compute primitive bodies, then dedupe by
    canonical circular signature (one entry per distinct loop).
    """
    raw_loops = detect_loops_fast(branches, min_iters=min_iters)
    unique = {}

    for i, L, count in raw_loops:
        # compute primitive period p
        vals = [(int(b['pc'],16)<<1)|b['direction'] for b in branches[i:i+L]]
        p = primitive_period(vals)

        # slice true iterations
        total_true = (count * L) // p
        iters = [
            branches[i + k*p : i + (k+1)*p]
            for k in range(total_true)
        ]
        first = iters[0]
        # original signature
        sig = tuple(b['pc'] for b in first)
        # canonical (rotation-normalized) signature
        can_sig = canonical_rotation(sig)

        # pick earliest i for each canonical signature
        if can_sig not in unique or i < unique[can_sig]['start_index']:
            unique[can_sig] = {
                'start_index': i,
                'body_len':    p,
                'iterations':  iters,
                'header_pc':   first[0]['pc']
            }

    return sorted(unique.values(), key=lambda x: x['start_index'])

def detect_loops_by_header(branches):
    """
    Returns a dict mapping:
       header_pc (hex str) -> list of back_edge_indices (i where branch[i] jumped)
    """
    loops = {}
    for i in range(len(branches)-1):
        b = branches[i]
        if b['direction'] != 1:
            continue
        hdr_pc = branches[i+1]['pc']
        # numeric compare to detect backward jump
        if int(hdr_pc, 16) < int(b['pc'], 16):
            loops.setdefault(hdr_pc, []).append(i)
    return loops

def record_iterations_by_header(branches, loops_by_hdr):
    """
    Given the map from header_pc -> [edge_indices],
    slice out each iteration as the sequence between hdr_index and the back-edge index.
    """
    results = []
    for hdr, edge_is in loops_by_hdr.items():
        iterations = []
        for edge_i in edge_is:
            # find where this iteration started: scan backwards from edge_i
            # until we hit either the previous iteration’s edge or start of trace
            # simplest: assume immediate previous back-edge marks the prior header
            prev_edges = [j for j in edge_is if j < edge_i]
            start = max(prev_edges)+1 if prev_edges else 0
            # slice up to edge_i inclusive
            iterations.append(branches[start:edge_i+1])
        results.append({
            'header':     hdr,
            'iterations': iterations,
            'count':      len(iterations)
        })
    return results



def detect_loops_by_header(branches):
    loops = {}
    for i in range(len(branches)-1):
        b = branches[i]
        if b['direction'] != 1:
            continue
        hdr_pc = branches[i+1]['pc']
        if int(hdr_pc,16) < int(b['pc'],16):
            loops.setdefault(hdr_pc, []).append(i)
    return loops

def record_iterations_precise(branches, loops_by_hdr):
    """
    For each header PC with sorted back-edge indices [e0, e1, ..., e_{k-1}]:
      - Build exactly k-1 *complete* iterations:
          iteration j = branches[ e_j+1 : e_{j+1}+1 ]
      - Discard the prelude before e0 and the tail after e_{k-1}.
    """
    results = []
    for hdr_pc, edges in loops_by_hdr.items():
        edges = sorted(edges)
        iterations = []
        # only full iterations between edges[j] and edges[j+1]
        for j in range(len(edges)-1):
            start = edges[j]   + 1
            end   = edges[j+1] + 1  # include that back-edge
            iterations.append(branches[start:end])
        sizes = [len(it) for it in iterations]
        results.append({
            'header':     hdr_pc,
            'iterations': iterations,
            'count':      len(iterations),
            'min_size':   min(sizes) if sizes else 0,
            'max_size':   max(sizes) if sizes else 0,
        })
    return results

def filter_true_iterations(iterations):
    """
    Given a list of iteration-slices, keep only those whose length
    is close to the minimum length (i.e. the actual loop body).

    We take:
      s_min = min(len(it) for it in iterations)
      threshold = s_min * 1.5  # or s_min + some delta
    and keep only iterations with len <= threshold.
    """
    sizes = [len(it) for it in iterations]
    if not sizes:
        return [], 0, 0
    s_min = min(sizes)
    # allow up to 150% of the minimal size
    thresh = s_min * 1.5
    filtered = [it for it,sz in zip(iterations, sizes) if sz <= thresh]
    return filtered, s_min, max(len(it) for it in filtered) if filtered else (0,0)

def record_iterations_clean(branches, loops_by_hdr):
    results = []
    for hdr_pc, edges in loops_by_hdr.items():
        edges = sorted(edges)
        raw_iters = []
        # build all full iterations
        for j in range(len(edges)-1):
            start = edges[j] + 1
            end   = edges[j+1] + 1
            raw_iters.append(branches[start:end])

        # filter to the “true” loop bodies
        true_iters, mn, mx = filter_true_iterations(raw_iters)

        results.append({
            'header':     hdr_pc,
            'iterations': true_iters,
            'count':      len(true_iters),
            'min_size':   mn,
            'max_size':   mx,
        })
    return results

def build_header_positions(branches):
    """
    Map each PC to the sorted list of trace-indices where it occurs.
    """
    hdr_pos = {}
    for idx, b in enumerate(branches):
        hdr_pos.setdefault(b['pc'], []).append(idx)
    for pc in hdr_pos:
        hdr_pos[pc].sort()
    return hdr_pos

def record_iterations_by_positions(branches, loops_by_hdr):
    """
    loops_by_hdr: hdr_pc -> list of back-edge indices [e0,...,e_{k-1}]

    We:
      - Precompute hdr_positions[hdr_pc] = sorted indices where branches[idx].pc == hdr_pc
      - For each e_j, binary-search hdr_positions[hdr_pc] for the first hdr_idx > e_j => h_j
      - Form iterations j=0..k-2 as branches[h_j : h_{j+1}]
    """
    hdr_positions = build_header_positions(branches)
    results = []

    for hdr_pc, edges in loops_by_hdr.items():
        edges = sorted(edges)
        hdr_list = hdr_positions.get(hdr_pc, [])
        iterations = []
        # compute header occurrences for each back-edge
        headers = []
        for e in edges:
            # find first occurrence of hdr_pc strictly after e
            # binary search over hdr_list
            import bisect
            pos = bisect.bisect_right(hdr_list, e)
            if pos < len(hdr_list):
                headers.append(hdr_list[pos])
            else:
                # no matching header after this edge (shouldn't happen), skip
                headers.append(None)

        # now slice from each h_j to h_{j+1}
        for j in range(len(headers)-1):
            h_j   = headers[j]
            h_j1  = headers[j+1]
            if h_j is None or h_j1 is None:
                continue
            iterations.append(branches[h_j : h_j1])

        sizes = [len(it) for it in iterations]
        results.append({
            'header':     hdr_pc,
            'count':      len(iterations),
            'min_size':   min(sizes) if sizes else 0,
            'max_size':   max(sizes) if sizes else 0,
            'iterations': iterations
        })

    return results

def record_iterations_nonoverlap(branches, loops_by_hdr):
    """
    For each hdr_pc → [e0, e1, ..., e_{k-1}], produce k-1 non-overlapping iterations:
      I_j = branches[e_{j-1}+1 : e_j+1]   for j=1..k-1
    """
    results = []
    for hdr_pc, edges in loops_by_hdr.items():
        edges = sorted(edges)
        iters = []
        # start from second back-edge, slice from the previous edge
        for prev_e, curr_e in zip(edges, edges[1:]):
            start = prev_e + 1
            end   = curr_e + 1    # include the back-edge itself
            iters.append(branches[start:end])
        sizes = [len(it) for it in iters]
        results.append({
            'header':   hdr_pc,
            'iterations': iters,
            'count':    len(iters),
            'min_size': min(sizes) if sizes else 0,
            'max_size': max(sizes) if sizes else 0
        })
    return results

def extract_fixed_iterations(branches, loops_by_hdr):
    """
    For each loop header PC:
      - hdr_positions = sorted indices i where branches[i].pc == hdr_pc
      - deltas = [hdr_positions[j+1] - hdr_positions[j] for j in range(len)-1]
      - body_len = min(delta for delta>0)
      - iterations = [ branches[pos : pos+body_len] for pos in hdr_positions[:-1] ]
    """
    results = []
    for hdr_pc, back_edges in loops_by_hdr.items():
        # 1) get all trace‐indices where this PC occurs
        hdr_positions = [i+1 for i in sorted(back_edges)]  # +1 since back-edge lands at header next
        if len(hdr_positions) < 2:
            continue

        # 2) compute deltas between consecutive header appearances
        deltas = [
            hdr_positions[j+1] - hdr_positions[j]
            for j in range(len(hdr_positions)-1)
            if hdr_positions[j+1] > hdr_positions[j]
        ]
        if not deltas:
            continue

        body_len = min(deltas)

        # 3) extract fixed-size windows
        iterations = [
            branches[pos : pos + body_len]
            for pos in hdr_positions[:-1]
            if pos + body_len <= len(branches)
        ]

        sizes = [len(it) for it in iterations]
        results.append({
            'header':     hdr_pc,
            'body_len':   body_len,
            'count':      len(iterations),
            'min_size':   min(sizes),
            'max_size':   max(sizes),
            'iterations': iterations
        })

    return results

if __name__ == "__main__":
    # Smaller datafile for testing
    trace = parse_branch_file('/sputnik/toIntel/loopDetection/fp_test.txt')
    # Large datafile for measurements:
    #branches = parse_branch_file('/sputnik/toIntel/cbp2025/trace_files/media_0_traces.txt')

    #raw_loops  = detect_loops_fast(branches, min_iters=2)
    #loops_info = record_loop_iterations_primitives(branches, raw_loops)
    #unique_loops = filter_unique_loops(loops_info)
    #unique_loops.sort(key=lambda l: l['raw_length'], reverse=True)
    #final_loops = filter_maximal_loops_by_signature(loops_info)

    #final_loops = find_unique_loops_circular(branches, min_iters=2)

    loops_by_hdr = detect_loops_by_header(trace)
    detailed = extract_fixed_iterations(trace, loops_by_hdr)

    #filter out loops with less than 100 iterations
    #filtered = [loop for loop in detailed if loop['count'] >= 100]


    print(f"Found {len(detailed)} loops")

    # print first 10 iterations for each loop
    for loop in detailed:
        hdr = loop['header']
        cnt = loop['count']
        bl  = loop['body_len']
        mn  = loop['min_size']
        mx  = loop['max_size']
        print(f" Loop @ header={hdr}, with body length={bl}, iterations={cnt}")
        print(f"   Min size: {mn}, Max size: {mx}")
        for idx, it in enumerate(loop['iterations'][:3]):  # print first 10 iterations
            print(f"   Iteration {idx+1}:", [b['pc'] for b in it if len(b['pc']) < 50])

