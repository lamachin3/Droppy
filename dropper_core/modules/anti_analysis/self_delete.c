#include "anti_analysis.h"


BOOL DeleteSelf() {


	WCHAR					szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO	Delete = { 0 };
	HANDLE					hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename = NULL;
	const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
	SIZE_T					sRename = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);

	// allocating enough buffer for the 'FILE_RENAME_INFO' structure
	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
		DebugPrint("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// cleaning up the structuresF
	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	//--------------------------------------------------------------------------------------------------------------------------
	// marking the file for deletion (used in the 2nd SetFileInformationByHandle call) 
	Delete.DeleteFile = TRUE;

	// setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, wcslen(NewStream) * sizeof(WCHAR));

	//--------------------------------------------------------------------------------------------------------------------------

	// used to get the current file name
	if (GetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
		DebugPrint("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	//--------------------------------------------------------------------------------------------------------------------------
	// RENAMING

	// openning a handle to the current file
	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		DebugPrint("[!] CreateFileW [R] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


    WDebugPrint(L"[i] Renaming :$DATA to %s  ...", NEW_STREAM);

	// renaming the data stream
	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
		DebugPrint("[!] SetFileInformationByHandle [R] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
    WDebugPrint(L"[+] DONE \n");

	CloseHandle(hFile);

	//--------------------------------------------------------------------------------------------------------------------------
	// DELEING

	// openning a new handle to the current file
	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		// in case the file is already deleted
		return TRUE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
		DebugPrint("[!] CreateFileW [D] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    WDebugPrint(L"[i] DELETING ...\n");

	// marking for deletion after the file's handle is closed
	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
		DebugPrint("[!] SetFileInformationByHandle [D] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    WDebugPrint(L"[+] DONE \n");

	CloseHandle(hFile);

	//--------------------------------------------------------------------------------------------------------------------------

	// freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}