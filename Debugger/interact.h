/*interact.h用来实现一些交互式操作*/
#include<stdio.h>
#include<windows.h>
#include <vector>
#include <Tlhelp32.h>
#include "capstone/include/capstone.h"
#pragma comment(lib,"capstone/capstone.lib")
using namespace std;

/*保存CC断点要用到的信息*/
typedef struct BREAKPOINTINFO
{
	LPVOID addr = 0;//断点地址
	BYTE code = 0;//保存OPCODE
	BOOL once = FALSE;//是否一次性断点
}BREAKPOINTINFO, * PBREAKPOINTINFO;
/*保存内存断点要用到的信息*/
typedef struct MEMORYPOINTINFO
{
	DWORD64 addr = 0;//断点地址
	DWORD dwOldProtect;//原始内存权限
	DWORD dwNewProtect;//断点条件
}MEMORYPOINTINFO, * PMEMORYPOINTINFO;
/*调试进程信息*/
typedef struct DEBUGPROCESSINFO
{
	csh  cs_handle;//反汇编引擎句柄
	DWORD PID;//进程ID
	DWORD TID;//线程ID
	HANDLE hProcess;//保存进程句柄
	HANDLE hThread;//保存线程句柄
	DWORD ExceptionCode;//异常代码
	PVOID ExceptionAddress;//异常地址

}DEBUGPROCESSINFO, * PDEBUGPROCESSINFO;
/*反汇编单条指令*/
BOOL GetDisAsm(csh cshandle, HANDLE hProcess, LPVOID Address, PCHAR mnmonic, int len);
/*用来设置软件断点*/
BOOL SetSoftBreakPoint(DWORD PID, LPVOID Address, BOOL once);
/*修改TF标志位为单步模式*/
BOOL SetTFFlag(HANDLE hThread);
/*移除CC断点*/
VOID RemoveSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo, BOOL only, PVOID address);
/*恢复CC断点*/
VOID RecoverSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo, BOOL only, PVOID address);
/*清除断点*/
VOID clearBreakPoint(DEBUGPROCESSINFO ProcessInfo,PVOID address);
/*删除CC断点*/
BOOL DeleteSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo);
/*反汇编*/
BOOL Disassembly(DEBUGPROCESSINFO ProcessInfo, LPVOID Address, DWORD num);
/*获取寄存器*/
BOOL GetRegister(HANDLE hThread);
/*获取栈信息*/
BOOL GetStack(HANDLE hProcess, HANDLE hThread);
/*获取内存数据*/
BOOL GetMemory(HANDLE hProcess, DWORD Address);
/*查看模块*/
VOID GetModules(DWORD PID);
/*用来交互输入*/
BOOL GetCommend(DEBUGPROCESSINFO ProcessInfo);
/*用来处理异常调试事件*/
BOOL  ExceptionEvent(DEBUG_EVENT DebugEvent, csh cshandle);
/*查看断点*/
VOID  ViewBreakPoint(DEBUGPROCESSINFO ProcessInfo);
/*帮助信息*/
VOID GetHelp();
/*设置硬件断点*/
VOID SetHBreakPoint(HANDLE hThread, char* flag, DWORD len, DWORD Address);
/*命中后清除硬件断点*/
BOOL ClearHBreakPoint(DEBUGPROCESSINFO ProcessInfo);
/*设置内存断点*/
VOID SetMemBreakPoint(HANDLE hProcess, char* flag,DWORD Address);
/*dump*/
VOID Dump();
/*修改寄存器值*/
VOID ChengeRegValue(DEBUGPROCESSINFO ProcessInfo, char * flag,DWORD Value);
/*修改内存值*/
VOID ChengeMemValue(DEBUGPROCESSINFO ProcessInfo, DWORD Address, DWORD Value);