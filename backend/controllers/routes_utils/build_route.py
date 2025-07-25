import ast

from flask import request


PREPROCESSING_KEYS = [
    "injectors",
    "obfuscation",
    "loaders",
    "syscalls",
    "unhooking",
    "redirect_output",
    "etw_bypass",
    "amsi_bypass",
]


def extract_form_data():
    form_data = {}
    for key, value in request.form.items():
        try:
            form_data[key] = ast.literal_eval(value) if value else None
        except (ValueError, SyntaxError):
            form_data[key] = value
    return form_data

def process_dropper_config(dropper_config):
    dropper_config['preprocessing_macros'] = []

    for key in dropper_config:
        if not key in PREPROCESSING_KEYS or dropper_config[key] == None:
            continue
        
        value = dropper_config.get(key, "")
        if isinstance(value, list):
            dropper_config['preprocessing_macros'].extend([v.upper() for v in value if v.strip()])
        elif isinstance(value, str):
            dropper_config['preprocessing_macros'].append(value.strip().upper())
        else:
            dropper_config['preprocessing_macros'].append(value.upper())
    if dropper_config.get("debug"):
        dropper_config['preprocessing_macros'].append("DEBUG")
    
    dropper_config['hide_console'] = dropper_config.get('hide_console')

    if dropper_config.get("syscalls"):
        dropper_config["preprocessing_macros"].append(f"SYSCALL_ENABLED")
    
    if dropper_config["process_name"]:
        if dropper_config['process_name'].endswith(".exe"):
            dropper_config['process_name'] = f"{dropper_config['process_name']}.exe"
        dropper_config["preprocessing_macros"].append(f"PROCESS_NAME_ENABLED")

    dropper_config['out_filename'] = f"{dropper_config.get('filename')}{dropper_config.get('file_extension')}"
