/*
 	CreateMethods.h
		brad.antoniewicz@foundstone.com
		
		Contains headers for the thread creation functions.
		See CreateMethods.cpp for more information 

*/

struct NtCreateThreadExBuffer {
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
	}; 


typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
);

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef long (WINAPI *LPFUN_RtlCreateUserThread)(
		HANDLE,					// ProcessHandle
	    PSECURITY_DESCRIPTOR,	// SecurityDescriptor (OPTIONAL)
	    BOOLEAN,				// CreateSuspended
		ULONG,					// StackZeroBits
	    PULONG,					// StackReserved
		PULONG,					// StackCommit
	    PVOID,					// StartAddress
		PVOID,					// StartParameter (OPTIONAL)
	    PHANDLE,				// ThreadHandle
		PCLIENT_ID				// ClientID
);


#ifndef _WIN64
VOID suspendInjectResume(HANDLE hHandle, LPVOID loadLibAddr, LPVOID dllPathAddr);
#endif
HANDLE bCreateRemoteThread(HANDLE hHandle, LPVOID loadLibAddr, LPVOID dllPathAddr);
HANDLE bCreateUserThread(HANDLE hHandle, LPVOID loadLibAddr, LPVOID dllPathAddr);