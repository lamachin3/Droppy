def jenkins_one_at_a_time_hash(key, initial_seed=8):
    """
    Compute the Jenkins One-At-A-Time 32-bit hash for a given string.
    
    Args:
        key: String to hash
        initial_seed: Seed value for left shift (default: 8)
        
    Returns:
        32-bit hash value as an integer
    """
    hash_value = 0
    
    # Convert string to bytes if it's not already
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Process each byte
    for byte in key:
        hash_value += byte
        hash_value &= 0xFFFFFFFF  # Keep it 32-bit
        hash_value += (hash_value << initial_seed)
        hash_value &= 0xFFFFFFFF
        hash_value ^= (hash_value >> 6)
        hash_value &= 0xFFFFFFFF
    
    # Final avalanche
    hash_value += (hash_value << 3)
    hash_value &= 0xFFFFFFFF
    hash_value ^= (hash_value >> 11)
    hash_value &= 0xFFFFFFFF
    hash_value += (hash_value << 15)
    hash_value &= 0xFFFFFFFF
    
    print(f"Hash value: 0x{hash_value:08x}")
    return hash_value


# Example usage
if __name__ == "__main__":
    test_strings = ["VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", ""]
    
    for s in test_strings:
        print(f"String: '{s}'")
        jenkins_one_at_a_time_hash(s)
        print()
        
