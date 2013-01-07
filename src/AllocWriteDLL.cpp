/*
 	AllocWriteMethods.cpp
		brad.antoniewicz@foundstone.com

		These functions return the value to start execution, and set value of lpExecParam
	
*/
#include "LoadLibraryR.h"
#include <stdio.h>

LPTHREAD_START_ROUTINE AllocWriteDLL(HANDLE hTargetProcHandle, LPCSTR dllPath) {
	HANDLE hFile          = NULL;
	DWORD dwLength        = 0;
	DWORD dwBytesRead     = 0;
	DWORD dwReflectiveLoaderOffset = 0;
	LPVOID lpWriteBuff	  = NULL;
	LPVOID lpDllAddr = NULL;

	printf("\t[+] Allocating space for entire DLL\n");

	hFile = CreateFileA( dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if( hFile == INVALID_HANDLE_VALUE ) {
		printf("\n[!] ERROR: Could not open DLL!\n");
		return NULL;
	}

	dwLength = GetFileSize( hFile, NULL );
	if( dwLength == INVALID_FILE_SIZE || dwLength == 0 ) {
		printf("\n[!] ERROR: Invalid DLL file size!\n");
		return NULL;
	}
	lpWriteBuff = HeapAlloc( GetProcessHeap(), 0, dwLength );
	if( !lpWriteBuff ) {
		printf("\n[!] ERROR: Failed to allocate memory for DLL!\n");
		return NULL;
	}
	
	if( ReadFile( hFile, lpWriteBuff, dwLength, &dwBytesRead, NULL ) == FALSE ){
		printf("\n[!] ERROR: Failed to read DLL!\n");
		return NULL;
	}

	lpDllAddr = VirtualAllocEx(hTargetProcHandle, NULL, dwLength, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	printf("\t\t[+] Writing into the current process space at 0x%08x\n", lpDllAddr);

	if (WriteProcessMemory(hTargetProcHandle, lpDllAddr, lpWriteBuff, dwLength, NULL) == 0) {
		printf("\n[!] WriteProcessMemory Failed [%u]\n", GetLastError());
		return NULL;
	}

	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpWriteBuff);
	
	HeapFree( GetProcessHeap(), 0, lpWriteBuff );
	
	if( !dwReflectiveLoaderOffset ) {
		printf("\n[!] Error calculating Offset - Wrong Architecture?\n");
		return NULL;
	}

	return (LPTHREAD_START_ROUTINE) ( (ULONG_PTR) lpDllAddr + dwReflectiveLoaderOffset );

}

LPTHREAD_START_ROUTINE AllocWritePath(HANDLE hTargetProcHandle, LPCSTR dllPath, LPVOID *lpExecParam) {

	unsigned int writeLen = 0;
	LPVOID lpDllAddr = NULL;
	LPVOID lpWriteVal = NULL;
	LPVOID loadLibAddr = NULL;
	
	printf("\t[+] Allocating space for the path of the DLL\n");

	lpDllAddr = VirtualAllocEx(hTargetProcHandle, NULL, strlen(dllPath), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	printf("\t\t[+] Writing into the current process space at 0x%08x\n", lpDllAddr);
	if (WriteProcessMemory(hTargetProcHandle, lpDllAddr, dllPath, strlen(dllPath), NULL) == 0) {
		printf("\n[!] WriteProcessMemory Failed [%u]\n", GetLastError());
		return NULL;
	}

	*lpExecParam = (LPVOID *)lpDllAddr;
	
	printf("\t\t[+] Looking for LoadLibrary in kernel32\n");
	loadLibAddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (loadLibAddr == NULL) {
		printf("\n[!] Failed to find LoadLibrary in Kernel32! Quiting...\n");
		return NULL;
	}
	printf("\t\t[+] Found at 0x%08x\n",loadLibAddr);

	return (LPTHREAD_START_ROUTINE) loadLibAddr;
	
}
