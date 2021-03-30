#include "MyDebugger.h"

int main()
{
	/*ѡ��Ҫ���Եĳ���*/
	SelectProcdure();
	/*���е���ѭ��*/
	DebugLoop();

	return 0;
}
/*���������Ϣ*/
VOID DisplayError(char* Infor)
{
	char buf[MAX_PATH] = { 0 };
	sprintf_s(buf, "%s\n%d", Infor, GetLastError());
	MessageBoxA(NULL, buf, "ERROR!", MB_ICONEXCLAMATION);
	exit(EXIT_SUCCESS);
}
/*�������ڵ���״̬�Ľ���*/
BOOL MyDebugerPro()
{
	printf("[*]	��������Խ���·��:\n");
	char FilePath[MAX_PATH] = { 0 };
	scanf_s("%s", FilePath, MAX_PATH);
	PROCESS_INFORMATION ProcessInfo = { 0 };
	STARTUPINFOA StartupInfo = { sizeof(STARTUPINFOA) };
	BOOL ret = CreateProcessA(FilePath, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInfo);//�������Խ���
	if (!ret)
	{
		DisplayError("CraeteProcessA Error");
	}
	CloseHandle(ProcessInfo.hProcess);//й¶���
	CloseHandle(ProcessInfo.hThread);//й¶���
	system("cls");
	return ret;
}
/*���ӽ����б��еĽ���*/
VOID EnumProcess()
{
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//�Ľ��̿���
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		DisplayError("CreateToolhelp32Snapshot Error");
	}
	BOOL Ret = Process32First(hProcessSnap, &pe32);//ö�ٿ���
	printf("[*]	[����ID]	[��������]\n");
	while (Ret)
	{
		printf("[*]	[%d]		", pe32.th32ProcessID);
		printf("[%s]\n", (PWCHAR)pe32.szExeFile);
		Ret = Process32Next(hProcessSnap, &pe32);//��һ������Ϣ
	}
	printf("[*]	��������Խ���ID:\n");
	DWORD PID = 0;
	scanf_s("%d", &PID);
	if (!DebugActiveProcess(PID))
	{
		DisplayError("AttachProcess Error");
	}
	system("cls");
}
/*��ʼ��������쳣*/
csh  InitDisassemblyEngine()
{
	csh cs_handle = { 0 };//�������ɵ���capstone API�ľ��
	cs_opt_mem optionMem = { 0 };//�ڴ������������Ϊ�û��Զ�������ݲ���������malloc
	//������ʱʹ��Ĭ�ϵ�ϵͳ����
	optionMem.calloc = calloc;
	optionMem.free = free;
	optionMem.malloc = malloc;
	optionMem.realloc = realloc;
	optionMem.vsnprintf = vsprintf_s;

	cs_option(NULL, CS_OPT_MEM, (size_t)&optionMem);//���õ����������������ʱѡ��
	cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle);//��ʼ��cs���

	return cs_handle;
}
/*ѡ����Գ���*/
VOID SelectProcdure()
{
	while (TRUE)
	{
		printf("[1.]	�������Խ���\n");
		printf("[2.]	���ӵ��Խ���\n");
		char  input[MAX_PATH] = { 0 };
		scanf_s("%s", input, MAX_PATH);
		fflush(stdin);
		if (!memcmp(input, "1", 2))
		{
			MyDebugerPro();//�������Խ���
			break;
		}
		else if (!memcmp(input, "2", 2))
		{
			EnumProcess();//���ӽ���
			break;
		}
		else
		{
			system("cls");
			printf("[*]		��������\n");
		}
	}
}
/*����ѭ��*/
VOID DebugLoop()
{
	DEBUG_EVENT DebugEvent = { 0 };
	csh handle = { 0 };//���ڽ��շ��������capstone���
	/*��ʼcapstone����*/
	handle = InitDisassemblyEngine();
	BOOL ret = TRUE;
	while (WaitForDebugEvent(&DebugEvent, INFINITE))//�����ȴ�
	{
		switch (DebugEvent.dwDebugEventCode)
		{
			case EXCEPTION_DEBUG_EVENT://�쳣�����¼�
			{
				ret = ExceptionEvent(DebugEvent, handle);
				break;
			}
			case CREATE_PROCESS_DEBUG_EVENT://���̴����¼�
			{
				LPVOID ptrEntryPoint = DebugEvent.u.CreateProcessInfo.lpStartAddress;
				SetSoftBreakPoint(DebugEvent.dwProcessId, ptrEntryPoint, TRUE);//һ����CC�ϵ�
				break;
			}
			case EXIT_PROCESS_DEBUG_EVENT://�����˳��¼�
			{
				DebugActiveProcessStop(DebugEvent.dwProcessId);
				printf_s("[*]  �������˳�......");
				break;
			}
			case CREATE_THREAD_DEBUG_EVENT://�̴߳���
			{
				break;
			}
			case LOAD_DLL_DEBUG_EVENT://����dll
			{
				break;
			}
		}
		if (!ret)
		{
			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);//���Բ����쳣�������׳�
		}
		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
	}
}