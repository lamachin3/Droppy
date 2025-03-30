import os

def setup_config_header(precompil_flags, project_dir):
    flags = ""
    for flag in precompil_flags:
        flags += f"#define {flag}\n"
    
    with open(os.path.join(project_dir, "config.h"), "w") as config_file:
        config_file.write(flags)
