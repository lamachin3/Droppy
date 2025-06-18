import donut

def generate_shellcode_with_donut(exe_path, output_path):
    """
    Generates shellcode from an EXE file using the Donut Python library.

    :param exe_path: Path to the EXE file.
    :param output_path: Path to save the generated shellcode.
    """
    try:
        # Generate shellcode using the Donut library
        #shellcode = donut.create(file=exe_path, params=" --help")
        shellcode = donut.create(file=exe_path, params="41204")

        # Save the shellcode to the specified output path
        with open(output_path, 'wb') as output_file:
            output_file.write(shellcode)

        print(f"Shellcode successfully generated and saved to: {output_path}")

    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
if __name__ == "__main__":
    exe_path = "C:/Users/lamachin3/Downloads/SharpDump.exe"  # Replace with your EXE path
    output_path = "C:/Users/lamachin3/Downloads/EtwPatching/EtwPatching/x64/Debug/SharpDump.bin"  # Replace with your desired output path
    generate_shellcode_with_donut(exe_path, output_path)
