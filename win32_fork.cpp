// win32_fork.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

/*
 * fork.c
 * Experimental fork() on Windows.  Requires NT 6 subsystem or
 * newer.
 *
 * Copyright (c) 2012 William Pitcock <nenolod@dereferenced.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <assert.h>
#include <errno.h>
#include <process.h>
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include "ntport.h"
#include "forkdata.h"
#include "signal.h"

BOOL dbg_Log(char* DataBuffer)

{

	char* pathx = NULL;
	pathx = getcwd(NULL, 0);
	//::GetTempPathA(MAX_PATH, (LPSTR)strTempPath.c_str());
    std::string strTempPath = pathx;
	std::string strLogFile = strTempPath + "Log.txt";
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;
	OVERLAPPED strOverlapped = {};
	strOverlapped.Offset = 0xFFFFFFFF;
	strOverlapped.OffsetHigh = 0xFFFFFFFF;
	hFile = CreateFileA(strLogFile.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	char TimeMessage[MAX_PATH] = { 0 };
	SYSTEMTIME st;
	::GetLocalTime(&st);
	char szTime[26] = { 0 };
	sprintf_s(szTime, "%04d-%02d-%02d %02d:%02d:%02d %d ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
	sprintf_s(TimeMessage, "%s: %s\n", szTime, DataBuffer);
	DWORD dwBytesToWrite = (DWORD)strlen(TimeMessage);
	bErrorFlag = WriteFile(hFile, TimeMessage, dwBytesToWrite, NULL, &strOverlapped);
	if (bErrorFlag == FALSE)
	{
		return false;
	}
	CloseHandle(hFile);
	return true;
}

typedef struct _g_fork
{
	/* data */
	char* name;
	int b;
	_g_fork* next;
}g_fork, * p_g_fork;

//typedef  unsigned int  pid_t;

#ifdef __MINGW32__

#ifdef _DEBUG
typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
#endif


typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID EntryPoint;
	ULONG StackZeroBits;
	ULONG StackReserved;
	ULONG StackCommit;
	ULONG ImageSubsystem;
	WORD SubSystemVersionLow;
	WORD SubSystemVersionHigh;
	ULONG Unknown1;
	ULONG ImageCharacteristics;
	ULONG ImageMachineType;
	ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Size;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED	0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES		0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE		0x00000004

#define RTL_CLONE_PARENT				0
#define RTL_CLONE_CHILD					297

#endif
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED	0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES		0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE		0x00000004

#define RTL_CLONE_PARENT				0
#define RTL_CLONE_CHILD					297

typedef NTSTATUS(*RtlCloneUserProcess_f)(ULONG ProcessFlags,
	PSECURITY_DESCRIPTOR ProcessSecurityDescriptor /* optional */,
	PSECURITY_DESCRIPTOR ThreadSecurityDescriptor /* optional */,
	HANDLE DebugPort /* optional */,
	PRTL_USER_PROCESS_INFORMATION ProcessInformation);

//pid_t fork(void)
//{
//	HMODULE mod;
//	RtlCloneUserProcess_f clone_p;
//	RTL_USER_PROCESS_INFORMATION process_info;
//	NTSTATUS result;
//
//	mod = GetModuleHandle(L"ntdll.dll");
//	if (!mod)
//		return -ENOSYS;
//
//	clone_p = (RtlCloneUserProcess_f)GetProcAddress(mod, "RtlCloneUserProcess");
//	if (clone_p == NULL)
//		return -ENOSYS;
//
//	/* lets do this */
//	result = clone_p(RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &process_info);
//
//	if (result == RTL_CLONE_PARENT)
//	{
//		//HANDLE me = GetCurrentProcess();
//		HANDLE hp, ht;
//
//		hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)process_info.ClientId.UniqueProcess);
//		ht = OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)process_info.ClientId.UniqueThread);
//
//		ResumeThread(process_info.Thread);
//		CloseHandle(process_info.Process);
//		CloseHandle(process_info.Thread);
//
//		return (pid_t)process_info.ClientId.UniqueProcess;
//	}
//	else if (result == RTL_CLONE_CHILD)
//	{
//		/* fix stdio */
//		AllocConsole();
//		return 0;
//	}
//	else
//		return -1;
//
//	/* NOTREACHED */
//	return -1;
//}
extern "C" void mainCRTStartup(void* peb);

//这个函数需要把vs的堆栈检测函数给关掉
void sb_entry(void* peb) {
	DWORD rc;
	char buf[2048] = { 0 };
#ifdef _M_IX86
	// look at the explanation in fork.c for why we do these steps.
	if (1) {
		HANDLE h64Parent, h64Child;
		char* stk, * end;
		DWORD mb = (1 << 20);

		// if we found the events, then we're the product of a fork()
		if (CreateWow64Events(GetCurrentProcessId(),
			&h64Parent, &h64Child, TRUE)) {

			if (!h64Parent || !h64Child)
				return;

			// tell parent we're rolling
			SetEvent(h64Child);

			if (WaitForSingleObject(h64Parent, FORK_TIMEOUT) != WAIT_OBJECT_0) {
				return;
			}

			// if __forked is 0, we shouldn't have found the events
			if (!__forked)
				return;
		}

		// now create the stack 

		if (!__forked) {
			stk = (char*)VirtualAlloc(NULL, mb + 65536, MEM_COMMIT, PAGE_READWRITE);
			if (!stk) {
				ZeroMemory(buf, 2048);
				sprintf(buf, "virtual alloc in parent failed %d\n", GetLastError());
				dbg_Log(buf);
				return ;
			}
			end = stk + mb + 65536;
			end -= sizeof(char*);

			__fork_stack_begin = end;
			ZeroMemory(buf, 2048);
			sprintf(buf, "父进程 begin is 0x%08x\n", stk);
			dbg_Log(buf);
			__asm {mov esp, end }; //把当前栈给替换掉=-=牛批

			set_stackbase(end);
			heap_init();
		}
		else { // child process
			stk = (char*)__fork_stack_begin + sizeof(char*) - mb - 65536;

			//printf("子进程 begin is 0x%08x\n", stk);
			end = (char*)VirtualAlloc(stk, mb + 65536, MEM_RESERVE, PAGE_READWRITE);
			if (!end) {
				rc = GetLastError();
				ZeroMemory(buf, 2048);
				sprintf(buf, "virtual alloc1 in child failed %d\n", GetLastError());
				dbg_Log(buf);
				return ;
			}
			stk = (char*)VirtualAlloc(end, mb + 65536, MEM_COMMIT, PAGE_READWRITE);
			if (!stk) {
				rc = GetLastError();
				ZeroMemory(buf, 2048);
				sprintf(buf, "virtual alloc2 in child failed %d\n", GetLastError());
				dbg_Log(buf);
				return;
			}
			end = stk + mb + 65536;
			__asm {mov esp, end};
			set_stackbase(end);

			SetEvent(h64Child);

			CloseHandle(h64Parent);
			CloseHandle(h64Child);
		}
	}
#endif
	mainCRTStartup(peb);
}


int main(int argc, const char* argv[])
{
	//p_g_fork p = (g_fork*)malloc(sizeof(g_fork));
	//p->name = (char*)malloc(20);
	//memset(p->name, 0, 20);
	//memcpy(p->name, "wrench_test", 12);
	//p->b = 1;
	//p->next = NULL;
	///*-------------------------test2---------------------------*/
	//p_g_fork q = (g_fork*)malloc(sizeof(g_fork));
	//q->name = (char*)malloc(20);
	//memset(q->name, 0, 20);
	//memcpy(q->name, "cocok_test", 11);
	//q->b = 2;
	//q->next = NULL;

	//p->next = q;
	///*---------------------------------------------------------*/
	//printf("p->name:%s q->name:%s\n", p->name, p->next->name);
	////////////////////////////////////////////////////////////////////








	////////////////////////////////////////////////////////////////////
	init_stdio();
	nt_init_signals();
	fork_init();
	pid_t pid = fork();

	switch (pid) {
	case 0:
	{
		//FILE* f = fopen("C:\\Users\\Administrator\\Desktop\\forktest.txt", "w+"); //子进程
		//fprintf(f, "[Child process] p->name:%s q->name:%s\n", p->name, p->next->name);
		//fclose(f);
		//while (1) { Sleep(1000); }
		//printf("[Child process] p->name:%s q->name:%s\n", p->name, p->next->name);
		break;
	}
	case -1:
	{
		//FILE* f = fopen("C:\\Users\\Administrator\\Desktop\\forktest.txt", "w+"); //子进程
		//fprintf(f, "[Child process] p->name:%s q->name:%s\n", p->name, p->next->name);
		//fclose(f);
		////while (1) { Sleep(1000); }
		break;
	}

	default:
		//printf("这是父进程，获得子进程的Pid为: %d\n", pid);
		while (1) { Sleep(1000); }
		break;
	}
}


