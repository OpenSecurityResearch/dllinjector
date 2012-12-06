/*
	dllinjector - 
		brad.antoniewicz@foundstone.com

		This tool was initially written to support vminjector32.dll 
		and vminector64.dll. It was later extended to support 
		injecting DLLs on all Windows versions using a variety
		of methods. 

		vminjector credit:
			https://github.com/batistam/VMInjector


		Todo:
			1. Implement SetWindowsHookEx() Method
				http://www.kdsbest.com/?p=179
			2. Implement QueueUserAPC() Method
				http://webcache.googleusercontent.com/search?q=cache:G8i5oxOWbDMJ:www.hackforums.net/archive/index.php/thread-2442150.html+&cd=3&hl=en&ct=clnk&gl=us&client=firefox-a
			3. Implement RtlCreateUserThread() Method 
				http://syprog.blogspot.com/2012/05/createremotethread-bypass-windows.html?showComment=1338375764336#c4138436235159645886
				http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
			4. Implement PrivEscalation as per: 
				https://github.com/rapid7/metasploit-framework/tree/master/external/source/meterpreter/source/extensions/priv/server/elevate
				/metasploit/msf3/external/source/meterpreter/source/extensions/priv/server/elevate


*/

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dos.h>


#define VERSION 0.1
#define BUFSIZE 512

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


void suspendInjectResume(HANDLE hHandle, LPVOID loadLibAddr, LPVOID dllPathAddr) {
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
	
	DWORD firstThread = NULL;
	HANDLE targetThread = NULL;

	LPVOID scAddr;

	te.dwSize = sizeof(THREADENTRY32);
	te2.dwSize = sizeof(THREADENTRY32);
	ctx.ContextFlags = CONTEXT_FULL;

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
				if ( firstThread == NULL )
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


int SetDebugPrivileges(void) { 
	DWORD err = 0; 
	TOKEN_PRIVILEGES Debug_Privileges; 
	if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid)) return GetLastError(); 
	HANDLE hToken = 0; 
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) 
	{ 
		err = GetLastError();   
		if(hToken) CloseHandle(hToken); 
		return err; 
	} 

	Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	Debug_Privileges.PrivilegeCount = 1; 

	if(!AdjustTokenPrivileges(hToken, false, &Debug_Privileges, 0, NULL, NULL)) 
	{ 
		err = GetLastError(); 
		if(hToken) CloseHandle(hToken); 
	} 

	return err; 
}

HANDLE bCreateRemoteThread(HANDLE hHandle, LPVOID loadLibAddr, LPVOID dllPathAddr) {

	HANDLE hRemoteThread = NULL;

	LPVOID ntCreateThreadExAddr = NULL;
	printf("[+] Looking for NtCreateThreadEx...");
	ntCreateThreadExAddr = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");

	if( ntCreateThreadExAddr ) {
		printf("Found!\n");
		
		NtCreateThreadExBuffer ntbuffer;
		DWORD temp1 = 0; 
		DWORD temp2 = 0; 

		ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
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
		printf("Not Found!\n");
	}
	return NULL;

}

void injectDLL(DWORD procID, TCHAR *dllPath, unsigned int method) {
	HANDLE hHandle = NULL;
	HANDLE rThread = NULL;
	LPVOID createRemotethreadAddr = NULL;
	LPVOID dllPathAddr = NULL;
	LPVOID loadLibAddr = NULL;
	OSVERSIONINFO osver; 
	DWORD ret = 0;

	osver.dwOSVersionInfoSize = sizeof(osver);
	
	if (GetVersionEx(&osver))
	{	
		if (osver.dwMajorVersion == 5) {
			printf("\t[+] Detected Windows XP\n");
			hHandle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, 0, procID );
		}
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 0)
			printf("\t[+] Detected Windows Vista\n");
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 1)	{
			printf("\t[+] Detected Windows 7\n");
			printf("\t[+] Openning Process ID: %d\n", procID);
			hHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, procID );
		}
	}
	

	printf("\t[+] Allocating space for DLL Path\n");
	dllPathAddr = VirtualAllocEx(hHandle, 0, strlen(dllPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	printf("\t[+] Writing the DLL Path into the current process space at 0x%08x\n", dllPathAddr);
	if (WriteProcessMemory(hHandle, dllPathAddr, dllPath, strlen(dllPath), NULL) == 0) {
		printf("\n[!] WriteProcessMemory Failed! Exiting...\n");
		exit (-1);
	}

	printf("\t[+] Looking for LoadLibrary in kernel32\n");
	loadLibAddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (loadLibAddr == NULL) {
		printf("\n[!] Failed to find LoadLibrary in Kernel32! Quiting...\n");
		exit(-1);
	}
	printf("\t\t[+] Found at 0x%08x\n",loadLibAddr);

	printf("\n[+] Creating New Thread In Process\n");

	switch(method) {
		case 1: // NtCreateThreadEx
			rThread = bCreateRemoteThread(hHandle, loadLibAddr, dllPathAddr);
			if (rThread == NULL) {
				printf("\n[!] NtCreateThreadEx Failed! [%d] Exiting....\n", GetLastError());
				CloseHandle(hHandle);
				exit(-1);
			} else {
				printf("\t[+] Remote Thread created! [%d]\n", GetLastError());
				ret = WaitForSingleObject(rThread, INFINITE);
				if (ret) 
					printf("\n[!] Couldnt find DLL return Signal! [%d][%d]\n", GetLastError(), ret);
				//CloseHandle(rThread);
			}
			break;
		case 2: // CreateRemoteThread
			printf("\n[+] Looking for CreateRemoteThread...");
			createRemotethreadAddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "CreateRemoteThread");
			if (createRemotethreadAddr) {
				printf("Found!\n");
				rThread = CreateRemoteThread(hHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, dllPathAddr, 0, NULL);
				if (rThread == NULL) {
					printf("\n[!] CreateRemoteThread Failed! [%d] Exiting....\n", GetLastError());
					CloseHandle(hHandle);
					exit(-1);
				} else {
					printf("\t[+] Remote Thread created! [%d]\n", GetLastError());
					ret = WaitForSingleObject(rThread, INFINITE);
					if (ret) 
						printf("\n[!] Couldnt find DLL return Signal! [%d][%d]\n", GetLastError(), ret);
					//CloseHandle(rThread);
				}
			} else {
				printf("Not Found!\n");
			}
			break;
		case 3: // Suspend/Inject/Resume
			printf("\n[+] Trying Suspend/Inject/Resume\n");
			suspendInjectResume(hHandle, loadLibAddr, dllPathAddr);
			break;
		default:
			printf("\n[!] Unknown Injection Method WTF?!\n");
			exit(-1);
	}

	CloseHandle(hHandle);
	
}

void dumpProcs( void ) {
	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) } ;
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

	printf("[+] Dumping processes and PIDs..\n");

	if( hSnapshot == INVALID_HANDLE_VALUE )
		exit(-1);

	if( ! Process32First( hSnapshot, &pe32 ) ) {
		CloseHandle( hSnapshot );
		exit(-1);
	}

	do {
		printf("\t[%d]\t%s\n",pe32.th32ProcessID, pe32.szExeFile );
	} while( Process32Next( hSnapshot, &pe32 ) );
	
	CloseHandle( hSnapshot );
	
}

void help( char *processname ) {
	printf("\n");
	printf("\t-d\t\tDump Process Excutables and IDs\n");
	printf("\t-p PID\t\tPID to inject into (from -d)\n");
	printf("\t-l file.dll\tDLL to inject\n");
	printf("\t-n\t\tUse NtCreateThreadEx()\n");
	printf("\t-c\t\tUse CreateRemoteThread()\n");
	printf("\t-s\t\tUse Suspend/Inject/Resume\n");
	printf("\t-h\t\tthis help\n");
	printf("\n");
	printf("Usage:\n");
	printf("\t%s -d (To Dump processes and get the PID)\n", processname);
	printf("\t%s -p 1234 -l something.dll -n (Inject something.dll into process 1234)\n", processname);
	printf("\n");
	
}

int main( int argc, char *argv[] ) {
	bool is64bit;
	int i;
	unsigned int method=1;
	DWORD pid = NULL;
	LPCTSTR dll = NULL;
	TCHAR dllPath[BUFSIZE] = TEXT("");
	
	if(sizeof(void*) == 4)
		is64bit = false; // 32bit
	else
		is64bit = true; // 64bit

	printf("\nFoundstone DLL Injector v%1.1f\n", VERSION);
	printf("brad.antoniewicz@foundstone.com\n");
	printf("--------------------------------------------------------\n");

	for (i=1; i < argc; i++) {
		if( strcmp(argv[i] , "-d") == 0 ) {
			dumpProcs();
			exit(0);
		} else if ( strcmp(argv[i] , "-p") == 0 ) {
			if(i+1 != argc) {
				pid = atol(argv[i+1]);
				printf("[+] Targeting PID: %d\n",pid);
				i++;
				}
		} else if ( strcmp(argv[i] , "-l") == 0 ) {
			if(i+1 != argc) {
				dll = TEXT(argv[i+1]);
				printf("[+] Injecting DLL: %s\n",dll);
				i++;
				}
		} else if ( strcmp(argv[i] , "-n") == 0 ) {
			method = 1;
		} else if ( strcmp(argv[i] , "-c") == 0 ) {
			method = 2;
		} else if ( strcmp(argv[i] , "-s") == 0 ) {
			method = 3;
		} else {
			help(argv[0]);
			exit(0);
		}
	}

	if (pid == NULL || dll == NULL) {
		help(argv[0]);
		printf("\n[!] Error: Must define PID and DLL\n");
		exit(-1);
	}

	GetFullPathName(dll, BUFSIZE, dllPath, NULL);
	printf("[+] Full DLL Path: %s\n", dllPath);
	printf("[+] Setting Debug Privileges [%d]\n", SetDebugPrivileges());
	
	injectDLL(pid, dllPath, method);

	return 0;
}
