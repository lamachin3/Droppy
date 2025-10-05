import os
import struct
import math
import magic
from typing import Dict, Any, Optional, Tuple

# PE (Portable Executable) constants
PE_SIGNATURE_OFFSET = 0x3C
MACHINE_X86 = 0x014C
MACHINE_X64 = 0x8664
MACHINE_ARM64 = 0xAA64
MACHINE_ARM = 0x1C0

# Map of magic output to our standardized file types
FILE_TYPE_MAPPING = {
    'pe': 'Portable Executable',
    'elf': 'ELF Executable',
    'mach-o': 'Mach-O Binary',
    'text': 'Text File',
    'ascii': 'Text File',
    'dos': 'DOS Executable',
    'executable': 'Executable',
    'script': 'Script',
}

class FileAnalyzer:
    file_obj = None

    def __init__(self, file_obj: Any):
        self._magic_mime = magic.Magic(mime=True)
        self._magic_desc = magic.Magic()
        self.file_obj = file_obj

    def set_file_obj(self, file_obj: Any):
        self.file_obj = file_obj
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze a file and return its metadata.
        
        Args:
            file_obj: A file-like object with read(), seek(), and size attributes.
                     Must be open in binary mode ('rb').
        """
        if not self.file_obj:
            return {}
            
        try:
            file_type = self._detect_file_type()
            architecture = self._detect_architecture(file_type)
            
            return {
                'size': self._format_file_size(),
                'type': file_type,
                'architecture': architecture,
                'entropy': self._calculate_file_entropy(),
            }
        except Exception as e:
            return {
                'size': '0 B',
                'type': 'Unknown',
                'architecture': 'Unknown',
                'entropy': 0.0
            }

    def _detect_file_type(self) -> str:
        if not self.file_obj:
            return 'Unknown'
            
        current_pos = self.file_obj.tell()
        try:
            self.file_obj.seek(0)
            chunk = self.file_obj.read(4096)
            if not chunk:
                return 'Unknown'
                
            # Use instance variable instead of creating new Magic instances
            mime_type = self._magic_mime.from_buffer(chunk).lower()

            # Map MIME types to our standard types
            if any(pe_type in mime_type for pe_type in ('pe32', 'pe32+', 'portable-executable')):
                return 'Portable Executable'
            elif 'elf' in mime_type:
                return 'ELF Executable'
            elif 'mach-o' in mime_type:
                return 'Mach-O Binary'
            elif any(text_type in mime_type for text_type in ('text/', 'text/plain')):
                return 'Text File'
            elif 'executable' in mime_type:
                return 'Executable'
                
            # Try to get a more specific description
            description = self._magic_desc.from_buffer(chunk).lower()
            
            # Check for specific patterns in the description
            for pattern, mapped_type in FILE_TYPE_MAPPING.items():
                if pattern in description:
                    return mapped_type
                    
            return mime_type.split(';')[0].strip() or 'Unknown'
            
        except Exception as e:
            return f'Unknown ({str(e)})'
        finally:
            self.file_obj.seek(current_pos)
            
    def _detect_architecture(self, file_type: str) -> str:
        if file_type != 'Portable Executable':
            return 'N/A'
            
        return self._detect_pe_architecture()

    def _detect_pe_architecture(self) -> str:
        if not self.file_obj:
            return 'Unknown'
            
        current_pos = self.file_obj.tell()
        try:
            self.file_obj.seek(0)
            chunk = self.file_obj.read(4096)
            if not chunk:
                return 'Unknown'
                
            # Try to detect using magic first
            file_info = self._magic_desc.from_buffer(chunk).lower()
            
            # Check for common architecture patterns
            if 'pe32+' in file_info and 'x86-64' in file_info:
                return 'x64'
            elif 'pe32' in file_info and 'intel 80386' in file_info:
                return 'x86'
            elif 'arm64' in file_info:
                return 'ARM64'
            elif 'arm' in file_info and 'windows' in file_info:
                return 'ARM'
            elif 'mips' in file_info:
                return 'MIPS'
                
            # Fall back to manual PE header parsing
            return self._parse_pe_architecture_manually(chunk)
                
        except Exception as e:
            return f'Error: {str(e)}'
        finally:
            self.file_obj.seek(current_pos)
            
    def _parse_pe_architecture_manually(self, chunk: bytes) -> str:
        try:
            # PE signature offset in DOS header
            pe_signature_offset = 0x3C
            pe_signature = b'PE\0\0'
            
            # Check minimum required size
            if len(chunk) < pe_signature_offset + 6:
                return 'Unknown (header too small)'
                
            # Get PE header offset from DOS header
            pe_offset = struct.unpack('<I', chunk[pe_signature_offset:pe_signature_offset+4])[0]
            
            # Validate PE header is within our chunk
            if pe_offset + 6 > len(chunk):
                return 'Unknown (PE header out of range)'
                
            # Verify PE signature
            if chunk[pe_offset:pe_offset+4] != pe_signature:
                return 'Unknown (invalid PE signature)'
                
            # Get machine type (2 bytes after PE signature)
            machine = struct.unpack('<H', chunk[pe_offset+4:pe_offset+6])[0]
            
            # Map machine type to architecture
            arch_map = {
                MACHINE_X86: 'x86',
                MACHINE_X64: 'x64',
                MACHINE_ARM: 'ARM',
                MACHINE_ARM64: 'ARM64',
            }
            
            return arch_map.get(machine, f'Unknown (0x{machine:04X})')
            
        except (struct.error, IndexError) as e:
            return f'Unknown (parse error: {str(e)})'

    def _calculate_file_entropy(self) -> float:
        if not self.file_obj:
            return 0.0
            
        current_pos = self.file_obj.tell()
        try:
            self.file_obj.seek(0)
            data = self.file_obj.read()
            
            if not data:
                return 0.0
                
            # Calculate byte frequencies using collections.Counter
            freq = collections.Counter(data)
            size = len(data)
            entropy = 0.0
            
            # Calculate entropy using the formula: -sum(p * log2(p))
            for count in freq.values():
                p = count / size
                if p > 0:  # Avoid log2(0)
                    entropy -= p * math.log2(p)
                    
            return round(entropy, 2)
            
        except Exception as e:
            return 0.0
        finally:
            self.file_obj.seek(current_pos)

    def _format_file_size(self) -> str:
        if not self.file_obj:
            return '0 B'
        
        # Get file size
        current_pos = self.file_obj.tell()
        self.file_obj.seek(0, os.SEEK_END)
        file_size = self.file_obj.tell()
        self.file_obj.seek(current_pos)  # Reset position
        
        if not file_size:
            return '0 B'
            
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        
        while file_size >= 1024 and unit_index < len(units) - 1:
            file_size /= 1024.0
            unit_index += 1
            
        return f"{file_size:.1f} {units[unit_index]}"
