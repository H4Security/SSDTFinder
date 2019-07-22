

#include <cstdio>
#include <cstdlib>
#include <string>
#include <windows.h>
#include <psapi.h>
#include "vmmdll.h"
#include "NtdllFuncs.h"
#define IN
#define OUT
using namespace std;
#pragma comment(lib, "vmm.lib")



/*list of ntdll.dll exported function wiht index*/


static LPVOID BaseAddresses[4096]; 
DWORD cbNeeded;

/* GetOriginalImageBase routine
*
* Function responsible for retrieving the original PE ImageBase field,
* given a handle to the already loaded module.
*
* Since the provided module is already present in the memory, we can assume
* all the PE structures are valid.
*/
DWORDLONG GetOriginalImageBase(PVOID Module)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((DWORDLONG)Module + DosHeader->e_lfanew);
	return NtHeaders->OptionalHeader.ImageBase;
}
DWORDLONG KGetOriginalImageBase(ULONG64 Module)
{
	BYTE Read_Dos_Header[sizeof(_IMAGE_DOS_HEADER)];
	BYTE Read_Nt_header[sizeof(IMAGE_NT_HEADERS)];
	VMMDLL_MemRead(4, Module, Read_Dos_Header, sizeof(_IMAGE_DOS_HEADER));
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Read_Dos_Header;
	VMMDLL_MemRead(4, Module + DosHeader->e_lfanew, Read_Nt_header, sizeof(IMAGE_NT_HEADERS));
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)Read_Nt_header;// (PIMAGE_NT_HEADERS)((DWORDLONG)Module + DosHeader->e_lfanew);
	return NtHeaders->OptionalHeader.SizeOfImage;
}


/* GetDriverBaseAddr routine
*
* Function responsible for retrieving the actual driver Base Address.
*/
DWORDLONG GetDriverBaseAddr(const char* BaseName)
{
	
	/*
	// Get a list of all the drivers' Image Base Addresses 
	if (!EnumDeviceDrivers(BaseAddresses, sizeof(BaseAddresses), &cbNeeded)) return 0;
	*/
	CHAR FileName[MAX_PATH];

	/* Go thru the entire list */
	for (int i = 0; i<(int)(cbNeeded / sizeof(LPVOID)); i++)
	{
		/* For each image base, retrieve the driver's name */
		GetDeviceDriverBaseNameA(BaseAddresses[i], FileName, sizeof(FileName));

		/* In case of the current module being kernel, return its base */
		if (!_stricmp(FileName, BaseName)) return (DWORDLONG)BaseAddresses[i];
	}

	/* Should never get here */
	return 0;
}

/*
if the SSDT function out space of kernel try to get address space of the functions
*/

DWORDLONG GetModelBaseAddr( char* BaseName, DWORDLONG SsdtFunc)
{
	/*
	static LPVOID BaseAddresses[4096]; // XXX: let's assume there are at most 4096 active device drivers
	DWORD cbNeeded;

	// Get a list of all the drivers' Image Base Addresses 
	if (!EnumDeviceDrivers(BaseAddresses, sizeof(BaseAddresses), &cbNeeded)) return 0;
	*/
	//BaseName = new char[MAX_PATH];

	/* Go thru the entire list */
	for (int i = 0; i < (int)(cbNeeded / sizeof(LPVOID)); i++)
	{
		ULONG64 End = KGetOriginalImageBase((ULONG64)BaseAddresses[i]) + (ULONG64)BaseAddresses[i];
		if (SsdtFunc >= (DWORDLONG)BaseAddresses[i] && SsdtFunc <= End)
		{
			/* For each image base, retrieve the driver's name */
			GetDeviceDriverBaseNameA(BaseAddresses[i], BaseName, MAX_PATH);
			return 0;
		}
		

		/* In case of the current module being kernel, return its base */
		//if (!_stricmp(FileName, BaseName)) return (DWORDLONG)BaseAddresses[i];
	}
	strcpy_s(BaseName , MAX_PATH, "Unknow");
	/* Should never get here */
	return 0;
}
void printSSDTtabe(DWORDLONG pServiceTable, DWORD limit, PBYTE ServiceTable, DWORDLONG OrgKernelEnd)
{
	printf("_________________________________________________________________________________________\n");
	printf("-----------------------------SSDT--------------------------------------------------------\n");
	printf("_________________________________________________________________________________________\n");
	//.for(r $t0=0; @$t0<dwo(nt!KiServiceLimit); r $t0=@$t0+1){.printf "%y\n", nt!KiServiceTable+(dwo(nt!KiServiceTable+@$t0*4)>>4)}
	for (DWORD i=0; i < limit; i++)
	{
		//DWORD fun = (*(DWORD*)(UINT*)(ServiceTable + i)) >> 4;
		int SSdtVAlue = *(INT*)(ServiceTable + i * 4);
		int fun = _rotr64(SSdtVAlue, 4);
		DWORDLONG phFun = pServiceTable + fun;
		/*if (phFun > OrgKernelEnd)
		{
			char *BaseName= new char[MAX_PATH];;
			GetModelBaseAddr(BaseName, phFun);
			printf("[%d] this Function in the %s space  0x%jx\n", j, BaseName, phFun);
		}*/
			//printf("[%d] this Function not in the kernel space  0x%jx\n", j, phFun);
		 
		printf("[0x%jx] Retrieving the Function  0x%jx\n", i,phFun);
	}
}

void SSDTAnalysis(DWORDLONG pServiceTable, DWORD limit, PBYTE ServiceTable, DWORDLONG OrgKernelEnd, struct SSDTFun *ntdllTable,DWORD num)
{
	for (DWORD i = 0; i < num; i++)
	{
		int SSdtVAlue = *(INT*)(ServiceTable + ntdllTable[i].sid * 4);
		int fun = _rotr64(SSdtVAlue, 4);
		DWORDLONG phFun = pServiceTable + fun;
		PBYTE jmp = new BYTE[2];
		VMMDLL_MemRead(4, phFun, jmp, 2);
		if ((jmp[0] & 0xFF) && (jmp[1]& 0x25))
		{
			printf("[%d] this Function in the %s space  %02X, %02X\n", i, ntdllTable[i].funName, jmp[0], jmp[1]);
		}
		//printf("[%d] this Function in the %s space  0x%jx\n",i, ntdllTable[i].funName, phFun);
		//_rotr(x, n);
		/*if (phFun > OrgKernelEnd)
		{
			char *BaseName = new char[MAX_PATH];;
			GetModelBaseAddr(BaseName, phFun);
		//	if(!strcmp(BaseName,"Unknow"))
			printf("[%#04x] this Function %s in the %s space  0x%jx\n", ntdllTable[i].sid, ntdllTable[i].funName, BaseName, phFun);
		}*/
		//else
			//printf("[%d] this Function in the %s space  0x%jx\n", i, ntdllTable[i].funName, phFun);
		//printf("[%d] this Function not in the kernel space  0x%jx\n", j, phFun);
	//else 
	//	printf("[%d] Retrieving the Function  0x%jx\n", j,phFun);
	}
	return;
}
int main(int argc, char **argv)
{
	HMODULE hKernel;
	PVOID pFunction, pFunction2;
	const char * pointFunc = "_strnicmp";

	const char KernelName[] = "ntoskrnl.exe";
	bool pCommand = FALSE, cCommand =FALSE;
	if (argc <= 1)
	{
		printf("[-] please choose one of the functions:\n-p : Print the SSDT.\n-c : scan the SSDT for Hooking.");
	}
	else {
		for (int i = 0; i < argc; i++)
		{
			if (!strcmp(argv[i] ,"-p"))
				pCommand = TRUE;
			else if(!strcmp(argv[i], "-c"))
				cCommand = TRUE;
		}
	}
	//BYTE  KiSystemServiceStartSign[] = { 0x20,0xE7,0x83,0x07,0xEF,0xC1,0xF8,0x8B,0x0F,0xFF,0x25,0x0 };
	BYTE  KiSystemServiceStartSign[] = { 0x8b,0xf8,0xc1,0xef,0x07,0x83,0xe7,0x20,0x25,0xff,0x0f };

	puts("*** Microsoft WindowsNT X64 Kernel SSDT address finder //vx ***\n");
	EnumDeviceDrivers(BaseAddresses, sizeof(BaseAddresses), &cbNeeded);
	printf("[+] Loading the %s image into the process'es address space\n", KernelName);
	hKernel = LoadLibraryEx(KernelName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (hKernel == NULL)
	{
		printf("[-] LoadLibraryEx failed. LastError: 0x%.8x\n", (UINT)GetLastError());
		return 1;
	}

	printf("[+] Retrieving the _strnicmp %s function address\n", pointFunc);
	pFunction = (PVOID)GetProcAddress(hKernel, pointFunc);
	
	if (pFunction == NULL)
	{
		printf("[-] GetProcAddress failed. LastError: 0x%.8x\n", (UINT)GetLastError());
		return 1;
	}

	printf("[+] Obtaining some info about the %s module\n", KernelName);
	MODULEINFO KernelInfo;
	if (!GetModuleInformation(GetCurrentProcess(), hKernel, &KernelInfo, sizeof(KernelInfo)))
	{
		printf("[-] GetModuleInformation failed. LastError: 0x%.8x\n", (UINT)GetLastError());
		return 1;
	}
	printf("[+] Kernel ImageBase:   0x%jx\n", (UINT64)KernelInfo.lpBaseOfDll);
	printf("[+] Kernel SizeOfImage: 0x%jx\n", (UINT)KernelInfo.SizeOfImage);

	/* Calculate both the 'original' (according to the PE header) and current kernel image address ranges */
	DWORDLONG OrgKernelStart = GetOriginalImageBase(hKernel); 
	

	DWORDLONG Pkernel = GetDriverBaseAddr(KernelName);
	DWORDLONG OrgKernelEnd = Pkernel + KernelInfo.SizeOfImage;

	DWORDLONG pointFuncK = (DWORDLONG)pFunction -OrgKernelStart + Pkernel;

	printf("[+] address of function _strnicmp in kernel 0x%jx\n", pointFuncK);
	printf("[+] The last byte in the Kernel 0x%jx\n", OrgKernelEnd);


	LPCSTR argv2[] = { "-vvv","-device","pmem"," "  };
	argv2[0] = "-printf";
	argv2[1] = "-device";
	argv2[2] = "pmem";
	argv2[3] = "-identify";
	BOOL KiSSStartSign = FALSE;
	BOOL initVmmd = VMMDLL_Initialize(3, (LPSTR*)argv2);
	
	PBYTE Read = new BYTE[1000], pServiceTable = new BYTE[8], pServiceLimit = new BYTE[4];
	DWORD SSDTp, ServiceLimit;// = new BYTE[4];
	DWORDLONG pNextIP, SDtable, ServiceTable;// = new BYTE[8];
	PBYTE Finger = Read;
	PBYTE ServiceFun = NULL;
	if (initVmmd)
	{
		
		printf("[+] address of function in kernel 0x%jx\n", pointFuncK);
		//int i = sizeof(KiSystemServiceStartSign);
		
		memset(Read, 0, 1000);
		//memset(SSDTp, 0, 4);
		do
		{
			if (VMMDLL_MemRead(4, pointFuncK, Read, 1000))
			{
				Finger = Read;
				for (int i = 0; i < 1000 - sizeof(KiSystemServiceStartSign); i++, Finger++)
				{
					if (memcmp(Finger, KiSystemServiceStartSign, sizeof(KiSystemServiceStartSign)) == 0)
					{
						printf("[+] address of KiSystemServiceStart+0x7 in kernel 0x%jx\n", pointFuncK + i);
						//memcpy(&SSDTp, Finger + sizeof(KiSystemServiceStartSign) + 5, sizeof(DWORD));
						SSDTp = *(DWORD*)(UINT*)(Finger + sizeof(KiSystemServiceStartSign) + 5);
						pNextIP = pointFuncK + i + sizeof(KiSystemServiceStartSign) + 9;
						SDtable = pNextIP + SSDTp;
						printf("[+] address of KeServiceDescriptorTable in kernel 0x%jx\n", SDtable);
						VMMDLL_MemRead(4, SDtable, pServiceTable, 8);
						ServiceTable = *(DWORDLONG*)(uint64_t*)(pServiceTable);
						printf("[+] address of ServiceTable in kernel 0x%jx\n", ServiceTable);
						VMMDLL_MemRead(4, SDtable+0x10, pServiceLimit, 4);
						ServiceLimit = *(DWORD*)(UINT*)(pServiceLimit);
						printf("[+] the ServiceLimit in kernel is:  0x%jx\n", ServiceLimit);
						KiSSStartSign = TRUE;
						break;
					}
				}
			}
			else
			{
				//printf("[+] Can't read from kernel");
				printf("[-] VMMDLL_MemRead failed. LastError: 0x%.8x\n", (UINT)GetLastError());
				VMMDLL_Close();
				return 1;
			}
			//BOOL refresh = VMMDLL_Refresh(0);
			memset(Read, 0, 1000);
			pointFuncK+=1000;
		} while ((pointFuncK < OrgKernelEnd) && (!KiSSStartSign));
		if (KiSSStartSign)
		{
			ServiceFun = new BYTE[ServiceLimit*4];
			VMMDLL_MemRead(4, ServiceTable, ServiceFun, ServiceLimit*4);
			if (pCommand)
			{
				printSSDTtabe(ServiceTable, ServiceLimit, ServiceFun, OrgKernelEnd);
			}
			
		}
		LPCSTR lpFileName = "C:\\Windows\\System32\\ntdll.dll";
		DWORD num = 0;
		struct SSDTFun *ntdllTable = NULL;
		ExtractNtdll(lpFileName, num, *&ntdllTable);
		if(cCommand)
			SSDTAnalysis(ServiceTable, ServiceLimit, ServiceFun, OrgKernelEnd, ntdllTable, num);
		/*
		if (num != 0)
		{
			for (int i = 0; i < num; i++)
			{
				printf("[%04X] this Function in the %s space  \n", ntdllTable[i].sid, ntdllTable[i].funName);
			}
		}*/
		printf("[+] Done\n");
		VMMDLL_Close();
	}
	else
	{
		printf("[-] VMMDLL_Initialize failed. LastError: 0x%.8x\n", (UINT)GetLastError());
		return 1;
	}
		
	getchar();

	return 0;
}

