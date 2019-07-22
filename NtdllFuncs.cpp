#include "NtdllFuncs.h"


PVOID MapFile(
	_In_ LPCSTR lpFileName
)
{
	HANDLE hFile, hMapping;
	PVOID  pvImageBase = NULL;

	hFile = CreateFile(lpFileName,
		GENERIC_READ,
		FILE_SHARE_READ |
		FILE_SHARE_WRITE |
		FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hFile != INVALID_HANDLE_VALUE) {

		hMapping = CreateFileMapping(hFile,
			NULL,
			PAGE_READONLY | SEC_IMAGE,
			0,
			0,
			NULL);

		if (hMapping != NULL) {

			pvImageBase = MapViewOfFile(hMapping,
				FILE_MAP_READ, 0, 0, 0);

			CloseHandle(hMapping);
		}
		CloseHandle(hFile);
	}
	return pvImageBase;
}

VOID ExtractNtdll(
	_In_ LPCSTR lpFileName,
	DWORD &NumberOfNames,
	struct SSDTFun *&table)
{

	PIMAGE_FILE_HEADER       fHeader;
	PIMAGE_OPTIONAL_HEADER64 oh64 = NULL;
	PIMAGE_EXPORT_DIRECTORY  ExportDirectory = NULL;

	PULONG NameTableBase;
	PULONG FunctionsTableBase;
	PUSHORT NameOrdinalTableBase;

	PCHAR pvImageBase, FunctionName, FunctionAddress;
	SIZE_T FunctionNameLength;

	ULONG i, sid;
	int j = 0;
	CHAR outBuf[MAX_PATH * 2];

	pvImageBase = (PCHAR)MapFile(lpFileName);
	if (pvImageBase == NULL) {

		printf("cannot load input file\n", (UINT)GetLastError());

		return;
	}

	__try {

		fHeader = (PIMAGE_FILE_HEADER)((ULONG_PTR)pvImageBase +
			((PIMAGE_DOS_HEADER)pvImageBase)->e_lfanew + sizeof(DWORD));
		oh64 = (PIMAGE_OPTIONAL_HEADER64)((ULONG_PTR)fHeader +
			sizeof(IMAGE_FILE_HEADER));

		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pvImageBase +
			oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (ExportDirectory == NULL)
			__leave;

		NameTableBase = (PULONG)(pvImageBase + (ULONG)ExportDirectory->AddressOfNames);
		NameOrdinalTableBase = (PUSHORT)(pvImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
		FunctionsTableBase = (PULONG)((PCHAR)pvImageBase + (ULONG)ExportDirectory->AddressOfFunctions);

		//NumberOfNames = ExportDirectory->NumberOfNames;
		table = new SSDTFun[ExportDirectory->NumberOfNames];

		for (i = 0; i < ExportDirectory->NumberOfNames; i++)
		{

			FunctionName = (PCHAR)((PCHAR)pvImageBase + NameTableBase[i]);
			if (*(USHORT*)FunctionName == 'tN') {

				FunctionNameLength = strlen(FunctionName);
				if (FunctionNameLength <= MAX_PATH) {
					sid = (DWORD)-1;
					FunctionAddress = (CHAR *)((CHAR *)pvImageBase + FunctionsTableBase[NameOrdinalTableBase[i]]);

					if (*(UCHAR*)((UCHAR*)FunctionAddress + 3) == 0xB8) {
						sid = *(ULONG*)((UCHAR*)FunctionAddress + 4);
						//printf("[%04X] this Function in the %s space  \n", sid, FunctionName);
						strcpy(table[j].funName, FunctionName);// , FunctionNameLength);
						table[j].sid = sid;
						j++;
						//printf("[%04X] this Function in the %s space  \n", SSDTTable[i].sid, SSDTTable[i].funName);
					}

					else {
						OutputDebugStringA(FunctionName);
						OutputDebugStringA("\r\nscg: syscall value not found\r\n");
					}
				}
				else {
					OutputDebugStringA("\r\nscg: Unexpected function name length\r\n");

				}
			}

		}
	}

	__finally {

		UnmapViewOfFile(pvImageBase);
	}
	NumberOfNames = j;
}
