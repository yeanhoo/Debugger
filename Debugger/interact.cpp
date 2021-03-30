#include"interact.h"

vector <BREAKPOINTINFO> BreakList;//容器,存放CC断点的动态数组
vector <MEMORYPOINTINFO> MemoryList;//容器,存放内存断点的动态数组
BOOL First = TRUE;

/*用来设置软件断点*/
BOOL SetSoftBreakPoint(DWORD PID, LPVOID Address, BOOL once)
{
	BOOL ret = TRUE;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	BREAKPOINTINFO bpInfo = { Address };
	bpInfo.once = once;
	ReadProcessMemory(hProcess, Address, &bpInfo.code, 1, NULL);
	WriteProcessMemory(hProcess, Address, "\xCC", 1, NULL);
	BreakList.push_back(bpInfo);
	CloseHandle(hProcess);

	return ret;
}
/*修改TF标志位为单步模式*/
BOOL SetTFFlag(HANDLE hThread)
{
	BOOL ret = TRUE;
	// 获取线程环境块
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
	// 将TF标志位设置为1,单步执行,TF位是EFLAGS寄存器中的第8位(从0开始)
	ct.EFlags |= 0x100;
	SetThreadContext(hThread, &ct);

	return ret;
}
/*单步步过*/
BOOL SetStepFlag(DEBUGPROCESSINFO ProcessInfo)
{
	BOOL ret = TRUE;
	// 获取线程环境块
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(ProcessInfo.hThread, &ct);
	DWORD Address = ct.Eip;
	cs_insn* ins = nullptr;
	PCHAR buf[16] = { 0 };
	ReadProcessMemory(ProcessInfo.hProcess, (LPVOID)Address, buf, 16, NULL);//必须先ReadProcessMemory到调试器中
	cs_disasm(ProcessInfo.cs_handle, (uint8_t*)buf, (size_t)16, (uint64_t)Address, 0, &ins);
	if (!memcmp(ins->mnemonic, "call", 4) || !memcmp(ins->mnemonic, "rep", 3))
	{
		SetSoftBreakPoint(ProcessInfo.PID, (LPVOID)(Address + ins->size), TRUE);//一次性软断
	}
	else
	{
		SetTFFlag(ProcessInfo.hThread);
	}
	return ret;
}
/*移除CC断点*/
VOID RemoveSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo,BOOL only,PVOID address)
{
	if (only == TRUE)//修复单个断点
	{
		for (int i = 0; i < BreakList.size(); i++)
		{
			if (BreakList[i].addr == address)
			{
				CONTEXT ct = { CONTEXT_CONTROL };
				GetThreadContext(ProcessInfo.hThread,&ct);
				ct.Eip -= 1;
				SetThreadContext(ProcessInfo.hThread, &ct);
				WriteProcessMemory(ProcessInfo.hProcess, BreakList[i].addr,&(BreakList[i].code), 1, NULL);
				
			}
		}
	}
	else//修复所有断点
	{
		for (int i = 0; i < BreakList.size(); i++)
		{
			WriteProcessMemory(ProcessInfo.hProcess, BreakList[i].addr, &(BreakList[i].code), 1, NULL);
		}
	}

}
/*恢复CC断点*/
VOID RecoverSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo,BOOL only, PVOID address)
{
	if (only == TRUE)
	{
		for (int i = 0; i < BreakList.size(); i++)
		{
			if (BreakList[i].addr == address)
			{
				CONTEXT ct = { CONTEXT_CONTROL };
				GetThreadContext(ProcessInfo.hThread, &ct);
				ct.Eip -= 1;
				SetThreadContext(ProcessInfo.hThread, &ct);
				WriteProcessMemory(ProcessInfo.hProcess, BreakList[i].addr, "\xCC", 1, NULL);
			}
		}
	}
	else
	{
		for (int i = 0; i < BreakList.size(); i++)
		{
			CONTEXT cont = { 0 };
			cont.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(ProcessInfo.hThread, &cont);
			if (cont.Eip == (DWORD)(BreakList[i].addr))
			{
				break;//当断点是EIP时不需要恢复
			}
			WriteProcessMemory(ProcessInfo.hProcess, BreakList[i].addr, "\xCC", 1, NULL);
		}
	}
}
/*清除断点*/
VOID clearBreakPoint(DEBUGPROCESSINFO ProcessInfo, PVOID address)
{
	for (int i = 0; i < BreakList.size(); i++)
	{
		if (BreakList[i].addr == address)
		{
			WriteProcessMemory(ProcessInfo.hProcess, BreakList[i].addr, &(BreakList[i].code), 1, NULL);//修复后删除
			BreakList.erase(BreakList.begin() + i);
		}
	}
}
/*删除一次性CC断点*/
BOOL DeleteSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo)
{
	BOOL ret = FALSE;
	for (int i = 0; i < BreakList.size(); i++)
	{
		if ((ProcessInfo.ExceptionAddress == BreakList[i].addr) && (BreakList[i].once == TRUE))
		{
			RemoveSoftBreakPoint(ProcessInfo, TRUE, ProcessInfo.ExceptionAddress);//恢复OPCODE
			BreakList.erase(BreakList.begin() + i);
			ret = TRUE;
		}
	}
	return ret;
}
/*反汇编*/
BOOL Disassembly(DEBUGPROCESSINFO ProcessInfo, LPVOID Address, DWORD num)
{
	BOOL ret = TRUE;
	cs_insn* ins = nullptr;//读取指令位置内存指针
	PCHAR buff = new CHAR[num * 16]();
	RemoveSoftBreakPoint(ProcessInfo,FALSE,NULL);//清除CC
	DWORD dwWrite = 0;
	ReadProcessMemory(ProcessInfo.hProcess, (LPVOID)Address, buff, num * 16, &dwWrite);//不使用ReadProcessMemory函数可能造成反汇编失败
	int nCount = cs_disasm(ProcessInfo.cs_handle, (uint8_t*)buff, num * 16, (uint64_t)Address, 0, &ins);//接收反汇编指令
	for (DWORD i = 0; i < num; i++)
	{
		printf_s("%08X ---> ", (UINT)ins[i].address);


		int tmp = 0;
		while (ins[i].size)
		{
			printf_s("%02X", ins[i].bytes[tmp]);//循环打印机器码
			tmp++;
			ins[i].size -= 1;
		}
		printf_s("\t%s %s\t", ins[i].mnemonic, ins[i].op_str);
		printf_s("\n");
	}
	printf_s("\n");
	cs_free(ins, nCount);
	free(buff);
	//恢复CC
	RecoverSoftBreakPoint(ProcessInfo, FALSE, NULL);
	return ret;
}
/*获取寄存器*/
BOOL GetRegister(HANDLE hThread)
{
	BOOL ret = TRUE;
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
	printf_s("EAX = %08X\t", ct.Eax);
	printf_s("EBX = %08X\t", ct.Ebx);
	printf_s("ECX = %08X\t", ct.Ecx);
	printf_s("EDX = %08X\n", ct.Edx);
	printf_s("ESI = %08X\t", ct.Esi);
	printf_s("EDI = %08X\t", ct.Edi);
	printf_s("ESP = %08X\t", ct.Esp);
	printf_s("EBP = %08X\n", ct.Ebp);
	printf_s("\tEIP = %08X\t\t\t", ct.Eip);
	printf_s("EFLAGS = %08X\n", ct.EFlags);
	printf_s("CS = %04X  ", ct.SegCs);
	printf_s("SS = %04X  ", ct.SegSs);
	printf_s("DS = %04X  ", ct.SegDs);
	printf_s("ES = %04X  ", ct.SegEs);
	printf_s("FS = %04X  ", ct.SegFs);
	printf_s("GS = %04X \n", ct.SegGs);

	return ret;
}
/*获取栈信息*/
BOOL GetStack(HANDLE hProcess, HANDLE hThread)
{
	BOOL ret = TRUE;
	DWORD dwRead = 0;
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
	PDWORD buf[20] = { 0 };

	ReadProcessMemory(hProcess, (LPVOID)ct.Esp, buf, 4 * 20, &dwRead);
	int tmp = 0;
	while (tmp < 20)
	{
		printf_s("[%08X]\t%08X\n", ct.Esp + tmp * 4, buf[tmp]);
		tmp++;
	}
	return ret;
}
/*获取内存数据*/
BOOL GetMemory(HANDLE hProcess, DWORD Address)
{
	BOOL ret = TRUE;
	PDWORD buf[0x100] = { 0 };
	DWORD dwWrite = 0;
	ReadProcessMemory(hProcess, (LPVOID)Address, buf, 0x100, &dwWrite);
	for (int tmp = 0; (tmp*4) < dwWrite; tmp++)
	{
		if ( (tmp * 4) % 0x10 == 0)
		{
			printf_s("\n[%08X]\t", Address + tmp*4);//0x10为首地址
		}
		printf_s("%08X ", buf[tmp]);//单字节打印
	}
	printf_s("\n");


	return ret;
}
/*查看模块*/
VOID GetModules(DWORD PID)
{
	
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hSnap == INVALID_HANDLE_VALUE)
		return ;
	MODULEENTRY32 me = { sizeof(MODULEENTRY32) };
	if (!Module32First(hSnap, &me))
	{
		CloseHandle(hSnap);
		return ;
	}
	BOOL ret = TRUE;
	while (ret)
	{
		printf_s("[%08X]\t",me.modBaseAddr);
		printf_s("[%s]\n", (PWCHAR)me.szExePath);
		ret = Module32Next(hSnap, &me);
	}
}
/*查看断点*/
VOID  ViewBreakPoint(DEBUGPROCESSINFO ProcessInfo)
{
	printf_s("CC断点列表:\n");
	for (int i = 0; i < BreakList.size(); i++)
	{
		printf_s("[%d]\t%08X\n", i + 1 ,BreakList[i].addr);
	}
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(ProcessInfo.hThread, &ct);
	printf_s("DR断点列表:\n");
	//e0、r1、w3
	printf_s("[*]\tDR0 = %08X\t", ct.Dr0);//16-17
	DWORD flag = ct.Dr7 & 0x30000;
	if(ct.Dr0)
	{
		if (flag == 0x30000)
		{
			printf_s("W");
		}
		else if (flag == 0)
		{
			printf_s("E");
		}
		else
		{
			printf_s("R");
		}
	}
	printf_s("\n[*]\tDR1 = %08X\t", ct.Dr1);//20-21
	flag = ct.Dr7 & 0x300000;
	if (ct.Dr1)
	{
		if (flag == 0x300000)
		{
			printf_s("W");
		}
		else if (flag == 0)
		{
			printf_s("E");
		}
		else
		{
			printf_s("R");
		}
	}
	printf_s("\n[*]\tDR2 = %08X\t", ct.Dr2);//24-25
	flag = ct.Dr7 & 0x3000000;
	if (ct.Dr2)
	{
		if (flag == 0x3000000)
		{
			printf_s("W");
		}
		else if (flag == 0)
		{
			printf_s("E");
		}
		else
		{
			printf_s("R");
		}
	}
	printf_s("\n[*]\tDR3 = %08X\t", ct.Dr3);//28-29
	flag = ct.Dr7 & 0x30000000;
	if (ct.Dr3)
	{
		if (flag == 0x30000000)
		{
			printf_s("W");
		}
		else if (flag == 0)
		{
			printf_s("E");
		}
		else
		{
			printf_s("R");
		}
	}
	printf_s("\n内存断点列表:\n");
	for (int y = 0; y < MemoryList.size(); y++)
	{
		printf_s("[%d]\t%08X\t", y + 1, MemoryList[y].addr);
		if (MemoryList[y].dwNewProtect == PAGE_EXECUTE_WRITECOPY)
		{
			printf_s("R\n");
		}
		else if (MemoryList[y].dwNewProtect == PAGE_EXECUTE_READ)
		{
			printf_s("W\n");
		}
		else
		{
			printf_s("E\n");
		}
	}

}
/*硬件断点*/
VOID SetHBreakPoint(HANDLE hThread, char* flag, DWORD len,DWORD Address)
{
	DWORD type = 0,les = 0;
	if (flag)//类型
	{
		if (!strcmp(flag, "r"))
		{
			type = 1;//01
		}
		else if (!strcmp(flag, "w"))
		{
			type = 3;//11
		}
		else if (!strcmp(flag, "e"))
		{
			type = 0;//00
		}
	}
	if (len)//长度
	{
		if (len == 1)
		{
			les = 0;//01
		}
		else if (len == 2)
		{
			les = 1;//11
		}
		else if (len == 4)
		{
			les = 3;//00
		}
	}
	CONTEXT ct = {CONTEXT_DEBUG_REGISTERS};
	if (type == 1 || type == 3)//读写断点需要内存对齐
	{
		if (les == 1)//对齐粒度
		{
			Address = (Address % 2) ? (Address - (Address % 2)) : Address;
		}
		if (les == 3)
		{
			Address = (Address % 4) ? (Address - (Address % 4)) : Address;
		}
	}
	GetThreadContext(hThread,&ct);
	if (Address)
	{
		//00：执行         01：写入        11：读写
		//00：1字节       01：2字节      11：4字节
		if ((ct.Dr7 & 0x1) == 0)//0、2、4、6
		{
			//DR0空闲
			ct.Dr0 = Address;
			ct.Dr7 |= 0x1;
			ct.Dr7 |= (les *0x40000);//18-19
			ct.Dr7 |= (type * 0x10000);//16-17

		}
		else if ((ct.Dr7 & 0x4) == 0)
		{
			//DR1空闲
			ct.Dr1 = Address;
			ct.Dr7 |= 0x4;
			ct.Dr7 |= (les * 0x400000);
			ct.Dr7 |= (type * 0x100000);
		}
		else if ((ct.Dr7 & 0x10) == 0)
		{
			//DR2空闲
			ct.Dr2 = Address;
			ct.Dr7 |= 0x10;
			ct.Dr7 |= (les * 0x4000000);
			ct.Dr7 |= (type * 0x1000000);
		}
		else if ((ct.Dr7 & 0x40) == 0)
		{
			//DR3空闲
			ct.Dr3 = Address;
			ct.Dr7 |= 0x40;
			ct.Dr7 |= (les * 0x4000000);
			ct.Dr7 |= (type * 0x10000000);
		}
		else
		{
			printf_s("硬件断点已用完");
		}
	}
	SetThreadContext(hThread, &ct);
}
/*命中后清除硬件断点*/
BOOL ClearHBreakPoint(DEBUGPROCESSINFO ProcessInfo)
{
	//由于不是专业开发人员，这里不想实现过于复杂的清除与恢复，直接将硬件断点默认为一次性断点。命中即清除
	BOOL ret = FALSE;
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(ProcessInfo.hThread, &ct);

	if ((DWORD)ProcessInfo.ExceptionAddress == ct.Dr0)
	{
		ct.Dr7 = ct.Dr7 & 0xFFFFFFFE;//11111111111111111111111111111110
		ct.Dr0 = 0;
		ct.Dr6 = ct.Dr6 & 0xFFFFFFFE;
		ret = TRUE;
	}
	if ((DWORD)ProcessInfo.ExceptionAddress == ct.Dr1)
	{
		ct.Dr7 = ct.Dr7 & 0xFFFFFFFD;//11111111111111111111111111111101
		ct.Dr1 = 0;
		ct.Dr6 = ct.Dr6 & 0xFFFFFFFD;
		ret = TRUE;
	}
	if ((DWORD)ProcessInfo.ExceptionAddress == ct.Dr2)
	{
		ct.Dr7 = ct.Dr7 & 0xFFFFFFEF;//11111111111111111111111111110111
		ct.Dr2 = 0;
		ct.Dr6 = ct.Dr6 & 0xFFFFFFEF;
		ret = TRUE;
	}
	if ((DWORD)ProcessInfo.ExceptionAddress == ct.Dr3)
	{
		ct.Dr7 = ct.Dr7 & 0xFFFFFFDF;// 11111111111111111111111111011111
		ct.Dr3 = 0;
		ct.Dr6 = ct.Dr6 & 0xFFFFFFDF;
		ret = TRUE;
	}
	SetThreadContext(ProcessInfo.hThread, &ct);
	return ret;
}
/*内存断点*/
VOID SetMemBreakPoint(HANDLE hProcess, char* flag, DWORD Address)
{
	MEMORYPOINTINFO mbp = { 0 };
	mbp.addr = Address & 0xFFFFF000;
	for (int i = 0; i < MemoryList.size(); i++)
	{
		if (mbp.addr == MemoryList[i].addr)
		{
			printf_s("目标内存页已存在内存断点\n");
			return;//防止一页内存多个内存断点
		}
		
	}
	if(!strcmp(flag, "r"))
	{
		mbp.dwNewProtect = PAGE_NOACCESS;
		//暂时用内存访问断点代替
	}
	else if (!strcmp(flag, "w"))
	{
		mbp.dwNewProtect = PAGE_EXECUTE_READ;
	}
	else if (!strcmp(flag, "e"))
	{
		mbp.dwNewProtect = PAGE_READWRITE;
	}
	else
	{
		printf("不存在页面属性");
		return;
	}
	if ( !VirtualProtectEx(hProcess, (LPVOID)mbp.addr, 0x1000, mbp.dwNewProtect, &mbp.dwOldProtect))
	{
		printf_s("内存断点下达失败\n");
		return;
	}
	MemoryList.push_back(mbp);
}
/*dump*/
VOID Dump()
{}
/*改变寄存器值*/
VOID ChengeRegValue(DEBUGPROCESSINFO ProcessInfo, char * flag, DWORD Value)
{
	CONTEXT context = { CONTEXT_INTEGER };
	GetThreadContext(ProcessInfo.hThread, &context);
	if (!strcmp(flag, "eax")) //eax
	{
		context.Eax = Value;
	}
	else if (!strcmp(flag, "ebx"))//ebx
	{
		context.Ebx = Value;
	}
	else if (!strcmp(flag, "ecx"))//ecx
	{
		context.Ecx = Value;
	}
	else if (!strcmp(flag, "edx"))//edx
	{
		context.Edx = Value;
	}
	else if (!strcmp(flag, "edi"))//edi
	{
		context.Edi = Value;
	}
	else if (!strcmp(flag, "esi"))//esi
	{
		context.Esi = Value;
	}
	SetThreadContext(ProcessInfo.hThread, &context);
}
/*改变内存值*/
VOID ChengeMemValue(DEBUGPROCESSINFO ProcessInfo, DWORD Address, DWORD Value)
{
	SIZE_T writen = 0;
	WriteProcessMemory(ProcessInfo.hProcess, (LPVOID)Address, &Value, sizeof(DWORD), &writen);
	return;
}
/*用来交互输入*/
BOOL GetCommend(DEBUGPROCESSINFO ProcessInfo)
{
	BOOL ret = TRUE;
	char input[MAX_PATH] = { 0 };
	while (TRUE)
	{
		printf_s("\n>>");
		scanf_s("%s", input, MAX_PATH);
		if (!strcmp(input, "g") || !strcmp(input, "go"))
		{
			//让程序跑起来
			break;//break之后进行异常处理
		}
		else if (!strcmp(input, "u"))
		{
			//反汇编
			DWORD Address = 0, lines = 0;
			scanf_s("%x %d", &Address, &lines);
			Disassembly(ProcessInfo, (LPVOID)Address, lines);
		}
		else if (!strcmp(input, "r") || !strcmp(input, "reg"))
		{
			//查看寄存器
			GetRegister(ProcessInfo.hThread);
		}
		else if (!strcmp(input, "k"))
		{
			//栈信息
			GetStack(ProcessInfo.hProcess, ProcessInfo.hThread);
		}
		else if (!strcmp(input, "d") || !strcmp(input, "dd"))
		{
			DWORD Address = 0;
			scanf_s("%x", &Address);
			//查看内存
			GetMemory(ProcessInfo.hProcess, Address);
		}
		else if (!strcmp(input, "lm"))
		{
			//查看模块
			GetModules(ProcessInfo.PID);
		}
		else if (!strcmp(input, "bl"))
		{
			//查看断点
			ViewBreakPoint(ProcessInfo);
		}
		else if (!strcmp(input, "bp"))
		{
			//下CC断点
			DWORD Address = 0;
			scanf_s("%x", &Address, sizeof(DWORD));
			SetSoftBreakPoint(ProcessInfo.PID, (LPVOID)Address, TRUE);
		}
		else if (!strcmp(input, "ba"))
		{
			//下硬件断点
			DWORD Address = 0,len = 0;
			CHAR flag[MAX_PATH] = { 0 };
			scanf_s("%s", flag, MAX_PATH);
			scanf_s("%d %x",&len,&Address);
			SetHBreakPoint(ProcessInfo.hThread, flag, len, Address);
		}
		else if (!strcmp(input, "bm"))
		{
			//下内存断点
			DWORD Address = 0, len = 0;
			CHAR flag[MAX_PATH] = { 0 };
			scanf_s("%s", flag, MAX_PATH);
			scanf_s("%x", &Address);
			SetMemBreakPoint(ProcessInfo.hProcess, flag,Address);
		}
		else if (!strcmp(input, "bc"))
		{
			//清除断点
			DWORD Address = 0;
			scanf_s("%x", &Address);
			clearBreakPoint(ProcessInfo, (PVOID)Address);
		}
		else if (!strcmp(input, "t"))
		{
			//单步步入
			SetTFFlag(ProcessInfo.hThread);
			break;
		}
		else if (!strcmp(input, "p"))
		{
			//单步步过
			SetStepFlag(ProcessInfo);
			break;
		}
		else if (!strcmp(input, "er"))
		{
			//修改内存值.寄存器值
			DWORD value = 0;
			CHAR flag[MAX_PATH] = { 0 };
			scanf_s("%s", flag, MAX_PATH);
			scanf_s("%x",&value);
			ChengeRegValue(ProcessInfo, flag,value);
		}
		else if (!strcmp(input, "em"))
		{
			//修改内存值.寄存器值
			DWORD address = 0,value = 0;
			scanf_s("%x %x", &address ,&value);
			ChengeMemValue(ProcessInfo, address, value);
		}
		else if (!strcmp(input, "asm"))
		{
			//修改汇编
			/*通过 汇编引擎语句实现即可,如keystone引擎*/
			break;
		}
		else if (!strcmp(input, "dump"))
		{
			//dump内存
			//dump未决定是将展开后的PE重写回文件还是直接按内存粒度dump，暂未实现
			Dump();
		}
		else if (!strcmp(input, "h") || !strcmp(input, "help"))
		{
			//帮助
			GetHelp();
		}
		else
		{
			printf_s("!!!指令错误,重新输入\n");
		}

	}

	return ret;
}
/*获取帮助*/
VOID GetHelp()
{
	printf_s("[*]\tu\t反汇编代码\t格式：u address lines\n");
	printf_s("[*]\tr [reg]\t查看寄存器\n");
	printf_s("[*]\tk\t查看栈信息\n");
	printf_s("[*]\td [dd]\t查看内存数据\t格式：d address\n");
	printf_s("[*]\tlm\t查看已加载模块\n");
	printf_s("[*]\tbl\t查看断点列表\n");
	printf_s("[*]\tbp\t下CC断点\t格式：bp address\n");
	printf_s("[*]\tba\t下硬件断点\t格式：ba authority size address\n");
	printf_s("[*]\tbm\t下内存断点\t格式：bm address authority\n");
	printf_s("[*]\tbc\t清除CC断点\t格式：bc address \n");
	printf_s("[*]\tt\t单步步入\n");
	printf_s("[*]\tp\t单步步过\n");
	printf_s("[*]\ter\t修改寄存器的值\t格式：e eax value\n");
	printf_s("[*]\tem\t修改内存的值\t格式：e address value\n");
	printf_s("[*]\tasm\t修改反汇编\t格式：asm address command\n");
	printf_s("[*]\tdump\tdump内存\t格式：dump address size\n");
}
/*用来处理异常调试事件*/
BOOL  ExceptionEvent(DEBUG_EVENT DebugEvent, csh cshandle)
{
	BOOL ret = TRUE;
	//保存必要的调试进程信息,便于传参
	DEBUGPROCESSINFO ProcessInfo = { cshandle };
	ProcessInfo.PID = DebugEvent.dwProcessId;
	ProcessInfo.TID = DebugEvent.dwThreadId;
	ProcessInfo.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	ProcessInfo.hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	ProcessInfo.ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	ProcessInfo.ExceptionAddress = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	//第一次CC断点由系统生成，用户直接跳过
	if (First && ProcessInfo.ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		ProcessInfo.ExceptionAddress = (char*)ProcessInfo.ExceptionAddress + 1;
		First = FALSE;
		return ret;
	}
	/***********************************/
	/*异常分发流程,存在异常时系统会将异常信息发送给调试器,如果*/
	/*不存在调试器,或者调试器未处理该异常,将异常交给SEH,VEH顶级异常*/
	/*处理,在调用异常处理过程中未处理该异常,那么异常处理过程会返回进行第*/
	/*二次异常分发,如果第二次还没有处理,分发给异常端口处理，csrss.exe监听*/
	/***********************************/

	switch (ProcessInfo.ExceptionCode)
	{		
		//访问异常，内存断点相关VirtualProtect
		case EXCEPTION_ACCESS_VIOLATION:
		{
			DWORD64 MemAddress =   (DWORD)(ProcessInfo.ExceptionAddress) & 0xFFFFF000;//内存页
			DWORD64 MemAddress2 = DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1] & 0xFFFFF000;//第二个数组元素指定不可访问数据的虚拟地址
			for (int i = 0; i < MemoryList.size(); i++)
			{
				if (MemAddress == MemoryList[i].addr)
				{
					printf_s("内存断点--> %p\n", MemAddress);
					VirtualProtectEx(ProcessInfo.hProcess, (LPVOID)MemAddress, 0x1000, MemoryList[i].dwOldProtect, &MemoryList[i].dwNewProtect);//恢复访问
					//暂时将内存断点和硬件断点均写为一次性断点
					MemoryList.erase( MemoryList.begin() + i);
				}
				else if (MemAddress2 == MemoryList[i].addr)
				{
					printf_s("内存断点--> %p\n", MemAddress2);
					VirtualProtectEx(ProcessInfo.hProcess, (LPVOID)MemAddress2, 0x1000, MemoryList[i].dwOldProtect, &MemoryList[i].dwNewProtect);//恢复访问
					//暂时将内存断点和硬件断点均写为一次性断点
					MemoryList.erase(MemoryList.begin() + i);
				}
			}
			break;
		}
		//int3断点
		case EXCEPTION_BREAKPOINT:
		{
			//一次性断点在命中后修复即删除
			if (DeleteSoftBreakPoint(ProcessInfo))
			{	
				break;
			}
			//正常的INT 3断点
			else 
			{
				printf_s("命中硬件中断断点: %p\n", ProcessInfo.ExceptionAddress);
				RemoveSoftBreakPoint(ProcessInfo, TRUE, ProcessInfo.ExceptionAddress);//在反汇编函数里会统一进行修复
				break;
			}
		}
		//单步,调试寄存器断点
		case EXCEPTION_SINGLE_STEP:
		{
			if (ClearHBreakPoint(ProcessInfo))//拔出硬件断点
			{//硬件断点
				printf_s("命中硬件断点: %p\n", ProcessInfo.ExceptionAddress);
			}
			//单步无需处理
			//步过会将CC当成一次性断点，也无需处理
			break;
		}
		default:
		{
			printf_s("未处理异常类型(%08X): %p\n", ProcessInfo.ExceptionCode, ProcessInfo.ExceptionAddress);
			ret = FALSE;
			break;
		}
	}
	//反汇编
	Disassembly(ProcessInfo, ProcessInfo.ExceptionAddress, 10);//反汇编当前异常地址
	//交互输入
	GetCommend(ProcessInfo);

	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
	return ret;
}
