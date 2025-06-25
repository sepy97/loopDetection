def find_all_cycles(instructions):
    n = len(instructions)
    if n == 0: 
        return []
    
    # Precompute prefix hashes and power array for rolling hash.
    base = 257
    mod = 10**9 + 7
    prefix = [0] * (n + 1)
    power = [1] * (n + 1)
    for i in range(n):
        prefix[i+1] = (prefix[i] * base + instructions[i]) % mod
        power[i+1] = (power[i] * base) % mod

    def get_hash(i, j):
        # returns hash of instructions[i:j]
        return (prefix[j] - prefix[i] * power[j-i]) % mod

    cycles = []
    # Explore possible cycle lengths.
    for cycle_len in range(1, min(n // 2 + 1, 101)):
        i = 0
        while i <= n - cycle_len * 2:
            candidate_hash = get_hash(i, i + cycle_len)
            j = i + cycle_len
            count = 1
            while j + cycle_len <= n and get_hash(j, j + cycle_len) == candidate_hash:
                count += 1
                j += cycle_len
            if count > 1:
                cycles.append({
                    'start': i,
                    'cycle': instructions[i:i + cycle_len],
                    'repetitions': count
                })
                i = j  # Skip detected cycle block.
            else:
                i += 1
    print(f"Found {len(cycles)} cycles in the instruction sequence.")
    return cycles

# Example usage
if __name__ == "__main__":
    # Example instruction pcs list.
    instructions = [100, 200, 300, 100, 200, 300, 400, 500, 400, 500, 400, 500]
    cycles_found = find_all_cycles(instructions)
    for cyc in cycles_found:
        print(f"Cycle starting at index {cyc['start']} with pattern {cyc['cycle']} repeated {cyc['repetitions']} times.")
    for cyc in cycles_found:
        print(f"Cycle starting at index {cyc['start']} with pattern {cyc['cycle']} repeated {cyc['repetitions']} times.")
