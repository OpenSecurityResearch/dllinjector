/*
 	CreateMethods.cpp
		brad.antoniewicz@foundstone.com

		Contains the thread creation functions. 

		Currently implements:

			1. Suspend/Inject/Resume Method
			2. ntCreateThreadEx()
			3. RtlCreateUserThread()
*/



#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "ExecThread.h"
#include "AllocWriteDLL.h"

#ifndef _WIN64	
VOID suspendInjectResume(HANDLE hHandle, LPVOID loadLibAddr, LPVOID dllPathAddr) {
	/*
		This is a mixture from the following sites:

			http://syprog.blogspot.com/2012/05/createremotethread-bypass-windows.html
			http://www.kdsbest.com/?p=159

	*/

	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	HANDLE hSnapshot2 = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	HANDLE thread = NULL;
	THREADENTRY32	te;
	THREADENTRY32	te2;
	
	CONTEXT			ctx;
	DWORD firstThread = 0;
	HANDLE targetThread = NULL;

	LPVOID scAddr;

	int i;
	
	unsigned char sc[] = {
			// Push all flags
			0x9C,
			// Push all register
			0x60,
			// Push 3,4,5,6 (dllPathAddr)
			0x68, 0xAA, 0xAA, 0xAA, 0xAA, 
			// Mov eax, 8,9,10, 11 (loadLibAddr)
			0xB8, 0xBB, 0xBB, 0xBB, 0xBB,
			// Call eax
			0xFF, 0xD0,
			// Pop all register
			0x61,
			// Pop all flags
			0x9D,
			// Ret
			0xC3
		};

	te.dwSize = sizeof(THREADENTRY32);
	te2.dwSize = sizeof(THREADENTRY32);
	ctx.ContextFlags = CONTEXT_FULL;

	sc[3] = ((unsigned int) dllPathAddr & 0xFF);
	sc[4] = (((unsigned int) dllPathAddr >> 8 )& 0xFF);
	sc[5] = (((unsigned int) dllPathAddr >> 16 )& 0xFF);
	sc[6] = (((unsigned int) dllPathAddr >> 24 )& 0xFF);

	sc[8] = ((unsigned int) loadLibAddr & 0xFF);
	sc[9] = (((unsigned int) loadLibAddr >> 8 )& 0xFF);
	sc[10] = (((unsigned int) loadLibAddr >> 16 )& 0xFF);
	sc[11] = (((unsigned int) loadLibAddr >> 24 )& 0xFF);
	
	

	// Suspend Threads
	if(Thread32First(hSnapshot, &te)) {
		do {
			if(te.th32OwnerProcessID == GetProcessId(hHandle)) {
				if ( firstThread == 0 )
					firstThread = te.th32ThreadID;
				thread = OpenThread(THREAD_ALL_ACCESS | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
				if(thread != NULL) {
					printf("\t[+] Suspending Thread 0x%08x\n", te.th32ThreadID);
					SuspendThread(thread);
					CloseHandle(thread);
				} else {
					printf("\t[+] Could not open thread!\n");
				}
			}
		} while(Thread32Next(hSnapshot, &te));
	} else {
		printf("\t[+] Could not Thread32First! [%d]\n", GetLastError());
		CloseHandle(hSnapshot);
		exit(-1);
	}
	CloseHandle(hSnapshot);

	printf("\t[+] Our Launcher Code:\n\t");
	for (i=0; i<17; i++)
		printf("%02x ",sc[i]);
	printf("\n");
	//  Get/Save EIP, Inject
	printf("\t[+] Targeting Thread 0x%08x\n",firstThread);
	targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, firstThread);
	if (GetThreadContext(targetThread, &ctx) == 0) 
		printf("[!] GetThreadContext Failed!\n");
	printf("\t[+] Current Registers: \n\t\tEIP[0x%08x] ESP[0x%08x]\n", ctx.Eip, ctx.Esp);

	printf("\t[+] Saving EIP for our return\n");
	ctx.Esp -= sizeof(unsigned int);
	WriteProcessMemory(hHandle, (LPVOID)ctx.Esp, (LPCVOID)&ctx.Eip, sizeof(unsigned int), NULL);
	printf("\t\tEIP[0x%08x] ESP[0x%08x] EBP[0x%08x]\n", ctx.Eip, ctx.Esp, ctx.Ebp);

	scAddr = VirtualAllocEx(hHandle, NULL, 17, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("\t[+] Allocating 17 bytes for our Launcher Code [0x%08x][%d]\n", scAddr, GetLastError());

	printf ("\t[+] Writing Launcher Code into targetThread [%d]\n", WriteProcessMemory(hHandle, scAddr, (LPCVOID)sc, 17, NULL));

	printf("\t[+] Setting EIP to LauncherCode\n");
	ctx.Eip = (DWORD)scAddr;
	printf("\t\tEIP[0x%08x] ESP[0x%08x]\n", ctx.Eip, ctx.Esp);

	if (SetThreadContext(targetThread, &ctx) == 0) 
		printf("[!] SetThreadContext Failed!\n");

	// Resume Threads
	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	te.dwSize = sizeof(THREADENTRY32);

	if(Thread32First(hSnapshot2, &te2)) {
		do {
			if(te2.th32OwnerProcessID == GetProcessId(hHandle)) {
				thread = OpenThread(THREAD_ALL_ACCESS | THREAD_GET_CONTEXT, FALSE, te2.th32ThreadID);
				if(thread != NULL) {
					printf("\t[+] Resuming Thread 0x%08x\n", te2.th32ThreadID);
					ResumeThread(thread);
					if (te2.th32ThreadID == firstThread) 
						WaitForSingleObject(thread, 5000);
					CloseHandle(thread);
				} else {
					printf("\t[+] Could not open thread!\n");
				}
			}
		} while(Thread32Next(hSnapshot2, &te2));
	} else {
		printf("\t[+] Could not Thread32First! [%d]\n", GetLastError());
		CloseHandle(hSnapshot2);
		exit(-1);
	}
	CloseHandle(hSnapshot2);
}
#endif

HANDLE bCreateRemoteThread(HANDLE hHandle, LPVOID loadLibAddr, LPVOID dllPathAddr) {

	HANDLE hRemoteThread = NULL;

	LPVOID ntCreateThreadExAddr = NULL;
	NtCreateThreadExBuffer ntbuffer;
	DWORD temp1 = 0; 
	DWORD temp2 = 0; 

	ntCreateThreadExAddr = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");

	if( ntCreateThreadExAddr ) {
	
		ntbuffer.Size = sizeof(struct NtCreateThreadExBuffer);
		ntbuffer.Unknown1 = 0x10003;
		ntbuffer.Unknown2 = 0x8;
		ntbuffer.Unknown3 = &temp2;
		ntbuffer.Unknown4 = 0;
		ntbuffer.Unknown5 = 0x10004;
		ntbuffer.Unknown6 = 4;
		ntbuffer.Unknown7 = &temp1;
		ntbuffer.Unknown8 = 0;

		LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx)ntCreateThreadExAddr;
		NTSTATUS status = funNtCreateThreadEx(
										&hRemoteThread,
										0x1FFFFF,
										NULL,
										hHandle,
										(LPTHREAD_START_ROUTINE)loadLibAddr,
										dllPathAddr,
										FALSE,
										NULL,
										NULL,
										NULL,
										&ntbuffer
										);
		
		if (hRemoteThread == NULL) {
			printf("\t[!] NtCreateThreadEx Failed! [%d][%08x]\n", GetLastError(), status);
			return NULL;
		} else {
			return hRemoteThread;
		}
	} else {
		printf("\n[!] Could not find NtCreateThreadEx!\n");
	}
	return NULL;

}

HANDLE bCreateUserThread(HANDLE hHandle, LPVOID loadLibAddr, LPVOID dllPathAddr) {
	/*
		Provided help
			http://syprog.blogspot.com/2012/05/createremotethread-bypass-windows.html?showComment=1338375764336#c4138436235159645886
			http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
			http://www.rohitab.com/discuss/topic/39493-using-rtlcreateuserthread/
	*/


	HANDLE hRemoteThread = NULL;
	LPVOID rtlCreateUserAddr = NULL;
	
	CLIENT_ID cid;
	
	rtlCreateUserAddr = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlCreateUserThread");

	if( rtlCreateUserAddr ) {
	
		LPFUN_RtlCreateUserThread funRtlCreateUserThread = (LPFUN_RtlCreateUserThread)rtlCreateUserAddr;
		funRtlCreateUserThread(
					hHandle,			// ProcessHandle
					NULL,				// SecurityDescriptor (OPTIONAL)
					FALSE,				// CreateSuspended
					0,					// StackZeroBits
					0,					// StackReserved
					0,					// StackCommit
					(PVOID) loadLibAddr,// StartAddress
					(PVOID) dllPathAddr,// StartParameter (OPTIONAL)
					&hRemoteThread,		// ThreadHandle
					&cid				// ClientID
				);
		
		if (hRemoteThread == NULL) {
			printf("\t[!] RtlCreateUserThread Failed! [%d]\n", GetLastError());
			return NULL;
		} else {
			return hRemoteThread;
		}
	} else {
		printf("\n[!] Could not find RtlCreateUserThread!\n");
	}
	return NULL;

}