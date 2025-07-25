def ipv4_encoding(payload_data: bytes) -> list[str]:
    """
    Convert a byte array to multiple IPv4 addresses. Each IPv4 address is represented by 4 bytes.
    If the byte array length is not a multiple of 4, it will be padded with 0x00.
    
    Args:
        byte_array (list of int): A list of byte values.
        
    Returns:
        list of str: A list of IPv4 addresses in dotted decimal format.
    """
    if not payload_data:
        return []

    byte_array = bytearray(payload_data)

    # Pad with 0x00 to ensure length is a multiple of 4
    missing_bytes = len(byte_array) % 4
    while len(byte_array) % 4 != 0:
        byte_array.insert(-missing_bytes, 0x00)

    return [
        f"{byte_array[i]}.{byte_array[i+1]}.{byte_array[i+2]}.{byte_array[i+3]}"
        for i in range(0, len(byte_array), 4)
    ]

def ipv6_encoding(payload_data: bytes) -> list[str]:
    """
    Convert a byte array to multiple IPv6 addresses. Each IPv6 address is represented by 16 bytes.
    If the byte array length is not a multiple of 16, it will be padded with 0x00 at the end.

    Args:
        payload_data (bytes): A byte array.

    Returns:
        list of str: A list of IPv6 addresses in colon-separated hexadecimal format.
    """
    if not payload_data:
        return []

    byte_array = bytearray(payload_data)

    # Pad with 0x00 at the end to ensure length is a multiple of 16
    while len(byte_array) % 16 != 0:
        byte_array.append(0x00)

    ipv6_addresses = [
        ":".join(
            f"{byte_array[i + j]:02x}{byte_array[i + j + 1]:02x}"
            for j in range(0, 16, 2)
        )
        for i in range(0, len(byte_array), 16)
    ]

    return ipv6_addresses

def mac_encoding(payload_data: bytes) -> list[str]:
    """
    Convert a byte array to multiple MAC addresses. Each MAC address is represented by 6 bytes.
    If the byte array length is not a multiple of 6, it will be padded with 0x00 at the end.

    Args:
        payload_data (bytes): A byte array.

    Returns:
        list of str: A list of MAC addresses in colon-separated hexadecimal format.
    """
    if not payload_data:
        return []

    byte_array = bytearray(payload_data)

    # Pad with 0x00 at the end to ensure length is a multiple of 6
    while len(byte_array) % 6 != 0:
        byte_array.append(0x00)

    mac_addresses = [
        ":".join(
            f"{byte_array[i + j]:02x}"
            for j in range(6)
        )
        for i in range(0, len(byte_array), 6)
    ]

    return mac_addresses

def uuid_encoding(payload_data: bytes) -> list[str]:
    if not payload_data:
        return []

    byte_array = bytearray(payload_data)

    # Pad with 0x00 to ensure length is a multiple of 16
    missing_bytes = len(byte_array) % 16
    while len(byte_array) % 16 != 0:
        byte_array.append(0x00)

    return [
        f"{byte_array[i+3]:02x}{byte_array[i+2]:02x}{byte_array[i+1]:02x}{byte_array[i]:02x}-"
        f"{byte_array[i+5]:02x}{byte_array[i+4]:02x}-{byte_array[i+7]:02x}{byte_array[i+6]:02x}-"
        f"{byte_array[i+8]:02x}{byte_array[i+9]:02x}-{byte_array[i+10]:02x}{byte_array[i+11]:02x}"
        f"{byte_array[i+12]:02x}{byte_array[i+13]:02x}{byte_array[i+14]:02x}{byte_array[i+15]:02x}"
        for i in range(0, len(byte_array), 16)
    ]