import os
import re
import requests


def _extract_doxygen_elements(file_content, element_name):
    """
    Extracts the value of a specified element from Doxygen comments in a C header file.

    :param file_content: The content of the C header file as a string.
    :param element_name: The element name to search for (e.g., "name").
    :return: The value of the specified element if found, otherwise None.
    """
    # Regular expression pattern for extracting all occurrences of the element in Doxygen comments
    pattern = rf"/\*\*.*?@{re.escape(element_name)}\s+(.*?)(?=\n|\*/)"  
    
    # Find all matches
    matches = re.findall(pattern, file_content, re.DOTALL)

    # Return a list of trimmed values
    if matches:
        return [match.strip() for match in matches]
    return []


def _organize_dictionnary(modules_dict):   
    keys_to_remove = [module for module in modules_dict if len(modules_dict[module]) == 0]
    
    for module in keys_to_remove:
        modules_dict.pop(module, None)
    
    if "crypto" in modules_dict or "encoders" in modules_dict:
        modules_dict["obfuscation"] = modules_dict.get("crypto", []) + modules_dict.get("encoders", [])
        modules_dict.pop("crypto", None)
        modules_dict.pop("encoders", None)
    
    return dict(sorted(modules_dict.items()))


def _extract_doxygen_info(file_path):
    """
    Extracts @name and @brief from Doxygen comments in a given file.

    Args:
        file_path (str): Path to the .h file.

    Returns:
        list: List of dictionaries containing 'name', 'brief', and 'section'.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        file_content = file.read()

    # Extract @name and @brief sections
    names = _extract_doxygen_elements(file_content, 'name')
    briefs = _extract_doxygen_elements(file_content, 'brief')
    flags = _extract_doxygen_elements(file_content, 'flags')
    tags = _extract_doxygen_elements(file_content, 'tags')
    while len(tags) < len(names):
        tags.append("")

    # Extract the section name from the file path
    section = os.path.basename(os.path.dirname(file_path))

    # Combine the results into a list of dictionaries
    results = []
    for name, brief, flag, tag in zip(names, briefs, flags, tags):
        results.append({'brief': brief, 'name': name, 'section': section, 'flags': flag.split(","), 'tags': tag.split(",")})
    return results


def _build_module_dictionary(modules_path):
    """
    Builds a dictionary with module names and their corresponding Doxygen information.

    Args:
        modules_path (str): Path to the modules folder.

    Returns:
        dict: Dictionary with module names as keys and lists of Doxygen info as values.
    """
    module_dict = {}

    for root, dirs, files in os.walk(modules_path):
        for file in files:
            if file.endswith('.h'):
                file_path = os.path.join(root, file)
                module_name = os.path.basename(root)
                doxygen_info = _extract_doxygen_info(file_path)
                if module_name in module_dict:
                    module_dict[module_name].extend(doxygen_info)
                else:
                    module_dict[module_name] = doxygen_info

    return _organize_dictionnary(module_dict)


def fetch_available_modules():
    modules_path = os.path.join('..', 'dropper_core', 'modules')
    syscalls_paths = os.path.join('..', 'dropper_core', 'syscalls')

    modules_dict = _build_module_dictionary(modules_path)
    syscalls_dict = _build_module_dictionary(syscalls_paths)

    return {**modules_dict, **syscalls_dict}

def _fetch_exegol_executables():
    ressources_list = []
    response = requests.get("https://api.github.com/repos/ThePorgs/Exegol-resources/git/trees/main?recursive=1")
    exegol_ressources = response.json()

    for ressource in exegol_ressources.get("tree", []):
        if ressource.get("path", "").endswith(".exe"):
            ressources_list.append({
                "filename": ressource["path"].split("/")[-1],
                "url": f"https://raw.githubusercontent.com/ThePorgs/Exegol-resources/refs/heads/main/{ressource['path']}",
            })
            
    return ressources_list

def fetch_precompiled_executables():
    executables_list = []
    executables_list.extend(_fetch_exegol_executables())
    
    return executables_list