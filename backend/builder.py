import os
import subprocess

DROPPER_SOURCE = '../dropper_core/main.c'
OUTPUT_FILE = '../outputs/dropper.exe'

def build_dropper():
    try:
        print('🔨 Compiling Dropper...')
        result = subprocess.run(['gcc', '-o', OUTPUT_FILE, DROPPER_SOURCE, '-Wall'], capture_output=True, text=True)
        if result.returncode == 0:
            print('✅ Dropper compiled successfully!')
        else:
            print('❌ Compilation failed:', result.stderr)
    except Exception as e:
        print('⚠️ Error:', str(e))

if __name__ == '__main__':
    build_dropper()

