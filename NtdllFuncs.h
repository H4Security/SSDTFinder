
#ifndef _NtdllFuncs_H__
#define _NtdllFuncs_H__
#pragma once
#include<Windows.h>
#include <stdio.h>
//https://github.com/hfiref0x/SyscallTables/blob/master/Source/scg/main.c


#pragma warning(disable: 4996)
#define MAX_NAME          50
struct SSDTFun
{
	char funName[MAX_NAME];
	short sid;
};

PVOID MapFile(
	_In_ LPCSTR lpFileName);
VOID ExtractNtdll(
	_In_ LPCSTR lpFileName,
	DWORD &NumberOfNames,
	struct SSDTFun *&table);
#endif