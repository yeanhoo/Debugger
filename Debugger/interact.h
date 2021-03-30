/*interact.h����ʵ��һЩ����ʽ����*/
#include<stdio.h>
#include<windows.h>
#include <vector>
#include <Tlhelp32.h>
#include "capstone/include/capstone.h"
#pragma comment(lib,"capstone/capstone.lib")
using namespace std;

/*����CC�ϵ�Ҫ�õ�����Ϣ*/
typedef struct BREAKPOINTINFO
{
	LPVOID addr = 0;//�ϵ��ַ
	BYTE code = 0;//����OPCODE
	BOOL once = FALSE;//�Ƿ�һ���Զϵ�
}BREAKPOINTINFO, * PBREAKPOINTINFO;
/*�����ڴ�ϵ�Ҫ�õ�����Ϣ*/
typedef struct MEMORYPOINTINFO
{
	DWORD64 addr = 0;//�ϵ��ַ
	DWORD dwOldProtect;//ԭʼ�ڴ�Ȩ��
	DWORD dwNewProtect;//�ϵ�����
}MEMORYPOINTINFO, * PMEMORYPOINTINFO;
/*���Խ�����Ϣ*/
typedef struct DEBUGPROCESSINFO
{
	csh  cs_handle;//�����������
	DWORD PID;//����ID
	DWORD TID;//�߳�ID
	HANDLE hProcess;//������̾��
	HANDLE hThread;//�����߳̾��
	DWORD ExceptionCode;//�쳣����
	PVOID ExceptionAddress;//�쳣��ַ

}DEBUGPROCESSINFO, * PDEBUGPROCESSINFO;
/*����൥��ָ��*/
BOOL GetDisAsm(csh cshandle, HANDLE hProcess, LPVOID Address, PCHAR mnmonic, int len);
/*������������ϵ�*/
BOOL SetSoftBreakPoint(DWORD PID, LPVOID Address, BOOL once);
/*�޸�TF��־λΪ����ģʽ*/
BOOL SetTFFlag(HANDLE hThread);
/*�Ƴ�CC�ϵ�*/
VOID RemoveSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo, BOOL only, PVOID address);
/*�ָ�CC�ϵ�*/
VOID RecoverSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo, BOOL only, PVOID address);
/*����ϵ�*/
VOID clearBreakPoint(DEBUGPROCESSINFO ProcessInfo,PVOID address);
/*ɾ��CC�ϵ�*/
BOOL DeleteSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo);
/*�����*/
BOOL Disassembly(DEBUGPROCESSINFO ProcessInfo, LPVOID Address, DWORD num);
/*��ȡ�Ĵ���*/
BOOL GetRegister(HANDLE hThread);
/*��ȡջ��Ϣ*/
BOOL GetStack(HANDLE hProcess, HANDLE hThread);
/*��ȡ�ڴ�����*/
BOOL GetMemory(HANDLE hProcess, DWORD Address);
/*�鿴ģ��*/
VOID GetModules(DWORD PID);
/*������������*/
BOOL GetCommend(DEBUGPROCESSINFO ProcessInfo);
/*���������쳣�����¼�*/
BOOL  ExceptionEvent(DEBUG_EVENT DebugEvent, csh cshandle);
/*�鿴�ϵ�*/
VOID  ViewBreakPoint(DEBUGPROCESSINFO ProcessInfo);
/*������Ϣ*/
VOID GetHelp();
/*����Ӳ���ϵ�*/
VOID SetHBreakPoint(HANDLE hThread, char* flag, DWORD len, DWORD Address);
/*���к����Ӳ���ϵ�*/
BOOL ClearHBreakPoint(DEBUGPROCESSINFO ProcessInfo);
/*�����ڴ�ϵ�*/
VOID SetMemBreakPoint(HANDLE hProcess, char* flag,DWORD Address);
/*dump*/
VOID Dump();
/*�޸ļĴ���ֵ*/
VOID ChengeRegValue(DEBUGPROCESSINFO ProcessInfo, char * flag,DWORD Value);
/*�޸��ڴ�ֵ*/
VOID ChengeMemValue(DEBUGPROCESSINFO ProcessInfo, DWORD Address, DWORD Value);