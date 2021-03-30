#include "MyDebugger.h"

int main()
{
	/*选择要调试的程序*/
	SelectProcdure();
	/*进行调试循环*/
	DebugLoop();

	return 0;
}
/*输出错误信息*/
VOID DisplayError(char* Infor)
{
	char buf[MAX_PATH] = { 0 };
	sprintf_s(buf, "%s\n%d", Infor, GetLastError());
	MessageBoxA(NULL, buf, "ERROR!", MB_ICONEXCLAMATION);
	exit(EXIT_SUCCESS);
}
/*创建处于调试状态的进程*/
BOOL MyDebugerPro()
{
	printf("[*]	请输入调试进程路径:\n");
	char FilePath[MAX_PATH] = { 0 };
	scanf_s("%s", FilePath, MAX_PATH);
	PROCESS_INFORMATION ProcessInfo = { 0 };
	STARTUPINFOA StartupInfo = { sizeof(STARTUPINFOA) };
	BOOL ret = CreateProcessA(FilePath, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInfo);//启动调试进程
	if (!ret)
	{
		DisplayError("CraeteProcessA Error");
	}
	CloseHandle(ProcessInfo.hProcess);//泄露句柄
	CloseHandle(ProcessInfo.hThread);//泄露句柄
	system("cls");
	return ret;
}
/*附加进程列表中的进程*/
VOID EnumProcess()
{
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//拍进程快照
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		DisplayError("CreateToolhelp32Snapshot Error");
	}
	BOOL Ret = Process32First(hProcessSnap, &pe32);//枚举快照
	printf("[*]	[进程ID]	[进程名称]\n");
	while (Ret)
	{
		printf("[*]	[%d]		", pe32.th32ProcessID);
		printf("[%s]\n", (PWCHAR)pe32.szExeFile);
		Ret = Process32Next(hProcessSnap, &pe32);//下一进程信息
	}
	printf("[*]	请输入调试进程ID:\n");
	DWORD PID = 0;
	scanf_s("%d", &PID);
	if (!DebugActiveProcess(PID))
	{
		DisplayError("AttachProcess Error");
	}
	system("cls");
}
/*初始化反汇编异常*/
csh  InitDisassemblyEngine()
{
	csh cs_handle = { 0 };//用于生成调用capstone API的句柄
	cs_opt_mem optionMem = { 0 };//内存操作，可配置为用户自定义的内容操作函数如malloc
	//这里暂时使用默认的系统函数
	optionMem.calloc = calloc;
	optionMem.free = free;
	optionMem.malloc = malloc;
	optionMem.realloc = realloc;
	optionMem.vsnprintf = vsprintf_s;

	cs_option(NULL, CS_OPT_MEM, (size_t)&optionMem);//配置到反编译引擎的运行时选项
	cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle);//初始化cs句柄

	return cs_handle;
}
/*选择调试程序*/
VOID SelectProcdure()
{
	while (TRUE)
	{
		printf("[1.]	创建调试进程\n");
		printf("[2.]	附加调试进程\n");
		char  input[MAX_PATH] = { 0 };
		scanf_s("%s", input, MAX_PATH);
		fflush(stdin);
		if (!memcmp(input, "1", 2))
		{
			MyDebugerPro();//创建调试进程
			break;
		}
		else if (!memcmp(input, "2", 2))
		{
			EnumProcess();//附加进程
			break;
		}
		else
		{
			system("cls");
			printf("[*]		重新输入\n");
		}
	}
}
/*调试循环*/
VOID DebugLoop()
{
	DEBUG_EVENT DebugEvent = { 0 };
	csh handle = { 0 };//用于接收反汇编引擎capstone句柄
	/*初始capstone引擎*/
	handle = InitDisassemblyEngine();
	BOOL ret = TRUE;
	while (WaitForDebugEvent(&DebugEvent, INFINITE))//持续等待
	{
		switch (DebugEvent.dwDebugEventCode)
		{
			case EXCEPTION_DEBUG_EVENT://异常调试事件
			{
				ret = ExceptionEvent(DebugEvent, handle);
				break;
			}
			case CREATE_PROCESS_DEBUG_EVENT://进程创建事件
			{
				LPVOID ptrEntryPoint = DebugEvent.u.CreateProcessInfo.lpStartAddress;
				SetSoftBreakPoint(DebugEvent.dwProcessId, ptrEntryPoint, TRUE);//一次性CC断点
				break;
			}
			case EXIT_PROCESS_DEBUG_EVENT://进程退出事件
			{
				DebugActiveProcessStop(DebugEvent.dwProcessId);
				printf_s("[*]  进程已退出......");
				break;
			}
			case CREATE_THREAD_DEBUG_EVENT://线程创建
			{
				break;
			}
			case LOAD_DLL_DEBUG_EVENT://加载dll
			{
				break;
			}
		}
		if (!ret)
		{
			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);//忽略部分异常，程序抛出
		}
		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
	}
}