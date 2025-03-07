import os
import re

def extract_doxygen_elements(file_content, element_name):
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
    return [match.strip() for match in matches]

def extract_doxygen_info(file_path):
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
    names = extract_doxygen_elements(file_content, 'name')
    briefs = extract_doxygen_elements(file_content, 'brief')

    # Extract the section name from the file path
    section = os.path.basename(os.path.dirname(file_path))

    # Combine the results into a list of dictionaries
    results = []
    for name, brief in zip(names, briefs):
        results.append({'brief': brief, 'name': name, 'section': section})
    return results

def build_module_dictionary(modules_path):
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
                doxygen_info = extract_doxygen_info(file_path)
                if module_name in module_dict:
                    module_dict[module_name].extend(doxygen_info)
                else:
                    module_dict[module_name] = doxygen_info

    return module_dict

def fetch_available_modules():
    # Path to the modules folder
    modules_path = os.path.join('..\\dropper_core', 'modules')

    # Build the module dictionary
    return build_module_dictionary(modules_path)
