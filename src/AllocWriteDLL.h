/*
 	AllocWriteDLL.h
		brad.antoniewicz@foundstone.com
		
		Contains headers for the Alloc/Write/Determine Address functions.
		See AllocWriteDLL.cpp for more information 

*/

LPTHREAD_START_ROUTINE AllocWriteDLL(HANDLE hTargetProcHandle, LPCSTR dllPath);
LPTHREAD_START_ROUTINE AllocWritePath(HANDLE hTargetProcHandle, LPCSTR dllPath, LPVOID *lpExecParam);