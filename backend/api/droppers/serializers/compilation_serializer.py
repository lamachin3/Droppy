from rest_framework import serializers


class CompileDropperSerializer(serializers.Serializer):
    injector = serializers.ChoiceField(
        choices=["APC_INJECTION", "REMOTE_INJECTION", "EARLY_BIRD_INJECTION", "EARLY_CASCADE_INJECTION", None, ""]
    )
    loader = serializers.ChoiceField(
        choices=["IN_MEMORY", "FILE_MAPPING", "FUNCTION_STOMPING", None, ""]
    )
    obfuscation = serializers.ChoiceField(
        choices=[
            "XOR_ENCRYPTION", "AES_ENCRYPTION", "RC4_ENCRYPTION",
            "IPV4_OBFUSCATION", "IPV6_OBFUSCATION", "UUID_OBFUSCATION", "MAC_OBFUSCATION",
            None, ""
        ]
    )
    amsi_bypass = serializers.ChoiceField(
        choices=["JNE_BASED_AMSI_PATCH", None, ""]
    )
    etw_bypass = serializers.ChoiceField(
        choices=[
            "JMP_RET_BASED_ETW_PATCH", "CALL_BASED_ETW_PATCH",
            "SYSCALL_BASED_ETW_PATCH", "HBP_ETW_HOOKING",
            None, ""
        ]
    )
    unhooking = serializers.ChoiceField(
        choices=["KNOWN_DLLS_UNHOOKING", "SUSPENDED_PROCESS_UNHOOKING", None, ""]
    )
    syscalls = serializers.ChoiceField(
        choices=["SW3_SYSCALLS", "HW_SYSCALLS", None, ""]
    )

    shellcode_text = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    shellcode = serializers.FileField(required=False, allow_null=True)
    github_url = serializers.URLField(required=False, allow_blank=True)
    execution_args = serializers.CharField(required=False, allow_blank=True)
    remote_process_name = serializers.CharField(required=False, allow_blank=True)

    debug_mode = serializers.BooleanField(required=False)
    hide_console = serializers.BooleanField(required=False)
    redirect_output = serializers.BooleanField(required=False)
    
    filename = serializers.CharField(required=False, allow_blank=True)
    file_extension = serializers.ChoiceField(choices=[".exe"], required=False)

    def validate(self, data):
        if not data.get('shellcode') and not data.get('shellcode_text') and not data.get('github_url'):
            raise serializers.ValidationError("Either 'shellcode' or 'shellcode_text' or 'github_url' must be provided.")
        
        if type(data.get('remote_process_name')) == str and data.get('remote_process_name'):
            if not data.get('remote_process_name').endswith('.exe'):
                raise serializers.ValidationError("Remote process name must end with '.exe'.")
            if data.get('injector') not in ['REMOTE_INJECTION', 'EARLY_BIRD_INJECTION', 'EARLY_CASCADE_INJECTION']:
                raise serializers.ValidationError("Remote process name is only valid for remote injection methods.")
        
        return data
    