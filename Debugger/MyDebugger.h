/*MyDebugger.h包含创建调试器基本框架代码*/
#include"interact.h"

/*输出错误信息*/
VOID DisplayError(char* Infor);
/*创建处于调试状态的进程*/
BOOL MyDebugerPro();
/*附加进程列表中的进程*/
VOID EnumProcess();
/*选择调试程序*/
VOID SelectProcdure();
/*初始化反汇编异常*/
csh  InitDisassemblyEngine();
/*调试循环*/
VOID DebugLoop();

