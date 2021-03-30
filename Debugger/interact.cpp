#include"interact.h"

vector <BREAKPOINTINFO> BreakList;//����,���CC�ϵ�Ķ�̬����
vector <MEMORYPOINTINFO> MemoryList;//����,����ڴ�ϵ�Ķ�̬����
BOOL First = TRUE;

/*������������ϵ�*/
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
/*�޸�TF��־λΪ����ģʽ*/
BOOL SetTFFlag(HANDLE hThread)
{
	BOOL ret = TRUE;
	// ��ȡ�̻߳�����
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
	// ��TF��־λ����Ϊ1,����ִ��,TFλ��EFLAGS�Ĵ����еĵ�8λ(��0��ʼ)
	ct.EFlags |= 0x100;
	SetThreadContext(hThread, &ct);

	return ret;
}
/*��������*/
BOOL SetStepFlag(DEBUGPROCESSINFO ProcessInfo)
{
	BOOL ret = TRUE;
	// ��ȡ�̻߳�����
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(ProcessInfo.hThread, &ct);
	DWORD Address = ct.Eip;
	cs_insn* ins = nullptr;
	PCHAR buf[16] = { 0 };
	ReadProcessMemory(ProcessInfo.hProcess, (LPVOID)Address, buf, 16, NULL);//������ReadProcessMemory����������
	cs_disasm(ProcessInfo.cs_handle, (uint8_t*)buf, (size_t)16, (uint64_t)Address, 0, &ins);
	if (!memcmp(ins->mnemonic, "call", 4) || !memcmp(ins->mnemonic, "rep", 3))
	{
		SetSoftBreakPoint(ProcessInfo.PID, (LPVOID)(Address + ins->size), TRUE);//һ�������
	}
	else
	{
		SetTFFlag(ProcessInfo.hThread);
	}
	return ret;
}
/*�Ƴ�CC�ϵ�*/
VOID RemoveSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo,BOOL only,PVOID address)
{
	if (only == TRUE)//�޸������ϵ�
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
	else//�޸����жϵ�
	{
		for (int i = 0; i < BreakList.size(); i++)
		{
			WriteProcessMemory(ProcessInfo.hProcess, BreakList[i].addr, &(BreakList[i].code), 1, NULL);
		}
	}

}
/*�ָ�CC�ϵ�*/
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
				break;//���ϵ���EIPʱ����Ҫ�ָ�
			}
			WriteProcessMemory(ProcessInfo.hProcess, BreakList[i].addr, "\xCC", 1, NULL);
		}
	}
}
/*����ϵ�*/
VOID clearBreakPoint(DEBUGPROCESSINFO ProcessInfo, PVOID address)
{
	for (int i = 0; i < BreakList.size(); i++)
	{
		if (BreakList[i].addr == address)
		{
			WriteProcessMemory(ProcessInfo.hProcess, BreakList[i].addr, &(BreakList[i].code), 1, NULL);//�޸���ɾ��
			BreakList.erase(BreakList.begin() + i);
		}
	}
}
/*ɾ��һ����CC�ϵ�*/
BOOL DeleteSoftBreakPoint(DEBUGPROCESSINFO ProcessInfo)
{
	BOOL ret = FALSE;
	for (int i = 0; i < BreakList.size(); i++)
	{
		if ((ProcessInfo.ExceptionAddress == BreakList[i].addr) && (BreakList[i].once == TRUE))
		{
			RemoveSoftBreakPoint(ProcessInfo, TRUE, ProcessInfo.ExceptionAddress);//�ָ�OPCODE
			BreakList.erase(BreakList.begin() + i);
			ret = TRUE;
		}
	}
	return ret;
}
/*�����*/
BOOL Disassembly(DEBUGPROCESSINFO ProcessInfo, LPVOID Address, DWORD num)
{
	BOOL ret = TRUE;
	cs_insn* ins = nullptr;//��ȡָ��λ���ڴ�ָ��
	PCHAR buff = new CHAR[num * 16]();
	RemoveSoftBreakPoint(ProcessInfo,FALSE,NULL);//���CC
	DWORD dwWrite = 0;
	ReadProcessMemory(ProcessInfo.hProcess, (LPVOID)Address, buff, num * 16, &dwWrite);//��ʹ��ReadProcessMemory����������ɷ����ʧ��
	int nCount = cs_disasm(ProcessInfo.cs_handle, (uint8_t*)buff, num * 16, (uint64_t)Address, 0, &ins);//���շ����ָ��
	for (DWORD i = 0; i < num; i++)
	{
		printf_s("%08X ---> ", (UINT)ins[i].address);


		int tmp = 0;
		while (ins[i].size)
		{
			printf_s("%02X", ins[i].bytes[tmp]);//ѭ����ӡ������
			tmp++;
			ins[i].size -= 1;
		}
		printf_s("\t%s %s\t", ins[i].mnemonic, ins[i].op_str);
		printf_s("\n");
	}
	printf_s("\n");
	cs_free(ins, nCount);
	free(buff);
	//�ָ�CC
	RecoverSoftBreakPoint(ProcessInfo, FALSE, NULL);
	return ret;
}
/*��ȡ�Ĵ���*/
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
/*��ȡջ��Ϣ*/
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
/*��ȡ�ڴ�����*/
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
			printf_s("\n[%08X]\t", Address + tmp*4);//0x10Ϊ�׵�ַ
		}
		printf_s("%08X ", buf[tmp]);//���ֽڴ�ӡ
	}
	printf_s("\n");


	return ret;
}
/*�鿴ģ��*/
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
/*�鿴�ϵ�*/
VOID  ViewBreakPoint(DEBUGPROCESSINFO ProcessInfo)
{
	printf_s("CC�ϵ��б�:\n");
	for (int i = 0; i < BreakList.size(); i++)
	{
		printf_s("[%d]\t%08X\n", i + 1 ,BreakList[i].addr);
	}
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(ProcessInfo.hThread, &ct);
	printf_s("DR�ϵ��б�:\n");
	//e0��r1��w3
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
	printf_s("\n�ڴ�ϵ��б�:\n");
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
/*Ӳ���ϵ�*/
VOID SetHBreakPoint(HANDLE hThread, char* flag, DWORD len,DWORD Address)
{
	DWORD type = 0,les = 0;
	if (flag)//����
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
	if (len)//����
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
	if (type == 1 || type == 3)//��д�ϵ���Ҫ�ڴ����
	{
		if (les == 1)//��������
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
		//00��ִ��         01��д��        11����д
		//00��1�ֽ�       01��2�ֽ�      11��4�ֽ�
		if ((ct.Dr7 & 0x1) == 0)//0��2��4��6
		{
			//DR0����
			ct.Dr0 = Address;
			ct.Dr7 |= 0x1;
			ct.Dr7 |= (les *0x40000);//18-19
			ct.Dr7 |= (type * 0x10000);//16-17

		}
		else if ((ct.Dr7 & 0x4) == 0)
		{
			//DR1����
			ct.Dr1 = Address;
			ct.Dr7 |= 0x4;
			ct.Dr7 |= (les * 0x400000);
			ct.Dr7 |= (type * 0x100000);
		}
		else if ((ct.Dr7 & 0x10) == 0)
		{
			//DR2����
			ct.Dr2 = Address;
			ct.Dr7 |= 0x10;
			ct.Dr7 |= (les * 0x4000000);
			ct.Dr7 |= (type * 0x1000000);
		}
		else if ((ct.Dr7 & 0x40) == 0)
		{
			//DR3����
			ct.Dr3 = Address;
			ct.Dr7 |= 0x40;
			ct.Dr7 |= (les * 0x4000000);
			ct.Dr7 |= (type * 0x10000000);
		}
		else
		{
			printf_s("Ӳ���ϵ�������");
		}
	}
	SetThreadContext(hThread, &ct);
}
/*���к����Ӳ���ϵ�*/
BOOL ClearHBreakPoint(DEBUGPROCESSINFO ProcessInfo)
{
	//���ڲ���רҵ������Ա�����ﲻ��ʵ�ֹ��ڸ��ӵ������ָ���ֱ�ӽ�Ӳ���ϵ�Ĭ��Ϊһ���Զϵ㡣���м����
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
/*�ڴ�ϵ�*/
VOID SetMemBreakPoint(HANDLE hProcess, char* flag, DWORD Address)
{
	MEMORYPOINTINFO mbp = { 0 };
	mbp.addr = Address & 0xFFFFF000;
	for (int i = 0; i < MemoryList.size(); i++)
	{
		if (mbp.addr == MemoryList[i].addr)
		{
			printf_s("Ŀ���ڴ�ҳ�Ѵ����ڴ�ϵ�\n");
			return;//��ֹһҳ�ڴ����ڴ�ϵ�
		}
		
	}
	if(!strcmp(flag, "r"))
	{
		mbp.dwNewProtect = PAGE_NOACCESS;
		//��ʱ���ڴ���ʶϵ����
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
		printf("������ҳ������");
		return;
	}
	if ( !VirtualProtectEx(hProcess, (LPVOID)mbp.addr, 0x1000, mbp.dwNewProtect, &mbp.dwOldProtect))
	{
		printf_s("�ڴ�ϵ��´�ʧ��\n");
		return;
	}
	MemoryList.push_back(mbp);
}
/*dump*/
VOID Dump()
{}
/*�ı�Ĵ���ֵ*/
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
/*�ı��ڴ�ֵ*/
VOID ChengeMemValue(DEBUGPROCESSINFO ProcessInfo, DWORD Address, DWORD Value)
{
	SIZE_T writen = 0;
	WriteProcessMemory(ProcessInfo.hProcess, (LPVOID)Address, &Value, sizeof(DWORD), &writen);
	return;
}
/*������������*/
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
			//�ó���������
			break;//break֮������쳣����
		}
		else if (!strcmp(input, "u"))
		{
			//�����
			DWORD Address = 0, lines = 0;
			scanf_s("%x %d", &Address, &lines);
			Disassembly(ProcessInfo, (LPVOID)Address, lines);
		}
		else if (!strcmp(input, "r") || !strcmp(input, "reg"))
		{
			//�鿴�Ĵ���
			GetRegister(ProcessInfo.hThread);
		}
		else if (!strcmp(input, "k"))
		{
			//ջ��Ϣ
			GetStack(ProcessInfo.hProcess, ProcessInfo.hThread);
		}
		else if (!strcmp(input, "d") || !strcmp(input, "dd"))
		{
			DWORD Address = 0;
			scanf_s("%x", &Address);
			//�鿴�ڴ�
			GetMemory(ProcessInfo.hProcess, Address);
		}
		else if (!strcmp(input, "lm"))
		{
			//�鿴ģ��
			GetModules(ProcessInfo.PID);
		}
		else if (!strcmp(input, "bl"))
		{
			//�鿴�ϵ�
			ViewBreakPoint(ProcessInfo);
		}
		else if (!strcmp(input, "bp"))
		{
			//��CC�ϵ�
			DWORD Address = 0;
			scanf_s("%x", &Address, sizeof(DWORD));
			SetSoftBreakPoint(ProcessInfo.PID, (LPVOID)Address, TRUE);
		}
		else if (!strcmp(input, "ba"))
		{
			//��Ӳ���ϵ�
			DWORD Address = 0,len = 0;
			CHAR flag[MAX_PATH] = { 0 };
			scanf_s("%s", flag, MAX_PATH);
			scanf_s("%d %x",&len,&Address);
			SetHBreakPoint(ProcessInfo.hThread, flag, len, Address);
		}
		else if (!strcmp(input, "bm"))
		{
			//���ڴ�ϵ�
			DWORD Address = 0, len = 0;
			CHAR flag[MAX_PATH] = { 0 };
			scanf_s("%s", flag, MAX_PATH);
			scanf_s("%x", &Address);
			SetMemBreakPoint(ProcessInfo.hProcess, flag,Address);
		}
		else if (!strcmp(input, "bc"))
		{
			//����ϵ�
			DWORD Address = 0;
			scanf_s("%x", &Address);
			clearBreakPoint(ProcessInfo, (PVOID)Address);
		}
		else if (!strcmp(input, "t"))
		{
			//��������
			SetTFFlag(ProcessInfo.hThread);
			break;
		}
		else if (!strcmp(input, "p"))
		{
			//��������
			SetStepFlag(ProcessInfo);
			break;
		}
		else if (!strcmp(input, "er"))
		{
			//�޸��ڴ�ֵ.�Ĵ���ֵ
			DWORD value = 0;
			CHAR flag[MAX_PATH] = { 0 };
			scanf_s("%s", flag, MAX_PATH);
			scanf_s("%x",&value);
			ChengeRegValue(ProcessInfo, flag,value);
		}
		else if (!strcmp(input, "em"))
		{
			//�޸��ڴ�ֵ.�Ĵ���ֵ
			DWORD address = 0,value = 0;
			scanf_s("%x %x", &address ,&value);
			ChengeMemValue(ProcessInfo, address, value);
		}
		else if (!strcmp(input, "asm"))
		{
			//�޸Ļ��
			/*ͨ�� ����������ʵ�ּ���,��keystone����*/
			break;
		}
		else if (!strcmp(input, "dump"))
		{
			//dump�ڴ�
			//dumpδ�����ǽ�չ�����PE��д���ļ�����ֱ�Ӱ��ڴ�����dump����δʵ��
			Dump();
		}
		else if (!strcmp(input, "h") || !strcmp(input, "help"))
		{
			//����
			GetHelp();
		}
		else
		{
			printf_s("!!!ָ�����,��������\n");
		}

	}

	return ret;
}
/*��ȡ����*/
VOID GetHelp()
{
	printf_s("[*]\tu\t��������\t��ʽ��u address lines\n");
	printf_s("[*]\tr [reg]\t�鿴�Ĵ���\n");
	printf_s("[*]\tk\t�鿴ջ��Ϣ\n");
	printf_s("[*]\td [dd]\t�鿴�ڴ�����\t��ʽ��d address\n");
	printf_s("[*]\tlm\t�鿴�Ѽ���ģ��\n");
	printf_s("[*]\tbl\t�鿴�ϵ��б�\n");
	printf_s("[*]\tbp\t��CC�ϵ�\t��ʽ��bp address\n");
	printf_s("[*]\tba\t��Ӳ���ϵ�\t��ʽ��ba authority size address\n");
	printf_s("[*]\tbm\t���ڴ�ϵ�\t��ʽ��bm address authority\n");
	printf_s("[*]\tbc\t���CC�ϵ�\t��ʽ��bc address \n");
	printf_s("[*]\tt\t��������\n");
	printf_s("[*]\tp\t��������\n");
	printf_s("[*]\ter\t�޸ļĴ�����ֵ\t��ʽ��e eax value\n");
	printf_s("[*]\tem\t�޸��ڴ��ֵ\t��ʽ��e address value\n");
	printf_s("[*]\tasm\t�޸ķ����\t��ʽ��asm address command\n");
	printf_s("[*]\tdump\tdump�ڴ�\t��ʽ��dump address size\n");
}
/*���������쳣�����¼�*/
BOOL  ExceptionEvent(DEBUG_EVENT DebugEvent, csh cshandle)
{
	BOOL ret = TRUE;
	//�����Ҫ�ĵ��Խ�����Ϣ,���ڴ���
	DEBUGPROCESSINFO ProcessInfo = { cshandle };
	ProcessInfo.PID = DebugEvent.dwProcessId;
	ProcessInfo.TID = DebugEvent.dwThreadId;
	ProcessInfo.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	ProcessInfo.hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	ProcessInfo.ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	ProcessInfo.ExceptionAddress = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	//��һ��CC�ϵ���ϵͳ���ɣ��û�ֱ������
	if (First && ProcessInfo.ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		ProcessInfo.ExceptionAddress = (char*)ProcessInfo.ExceptionAddress + 1;
		First = FALSE;
		return ret;
	}
	/***********************************/
	/*�쳣�ַ�����,�����쳣ʱϵͳ�Ὣ�쳣��Ϣ���͸�������,���*/
	/*�����ڵ�����,���ߵ�����δ������쳣,���쳣����SEH,VEH�����쳣*/
	/*����,�ڵ����쳣���������δ������쳣,��ô�쳣������̻᷵�ؽ��е�*/
	/*�����쳣�ַ�,����ڶ��λ�û�д���,�ַ����쳣�˿ڴ���csrss.exe����*/
	/***********************************/

	switch (ProcessInfo.ExceptionCode)
	{		
		//�����쳣���ڴ�ϵ����VirtualProtect
		case EXCEPTION_ACCESS_VIOLATION:
		{
			DWORD64 MemAddress =   (DWORD)(ProcessInfo.ExceptionAddress) & 0xFFFFF000;//�ڴ�ҳ
			DWORD64 MemAddress2 = DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1] & 0xFFFFF000;//�ڶ�������Ԫ��ָ�����ɷ������ݵ������ַ
			for (int i = 0; i < MemoryList.size(); i++)
			{
				if (MemAddress == MemoryList[i].addr)
				{
					printf_s("�ڴ�ϵ�--> %p\n", MemAddress);
					VirtualProtectEx(ProcessInfo.hProcess, (LPVOID)MemAddress, 0x1000, MemoryList[i].dwOldProtect, &MemoryList[i].dwNewProtect);//�ָ�����
					//��ʱ���ڴ�ϵ��Ӳ���ϵ��дΪһ���Զϵ�
					MemoryList.erase( MemoryList.begin() + i);
				}
				else if (MemAddress2 == MemoryList[i].addr)
				{
					printf_s("�ڴ�ϵ�--> %p\n", MemAddress2);
					VirtualProtectEx(ProcessInfo.hProcess, (LPVOID)MemAddress2, 0x1000, MemoryList[i].dwOldProtect, &MemoryList[i].dwNewProtect);//�ָ�����
					//��ʱ���ڴ�ϵ��Ӳ���ϵ��дΪһ���Զϵ�
					MemoryList.erase(MemoryList.begin() + i);
				}
			}
			break;
		}
		//int3�ϵ�
		case EXCEPTION_BREAKPOINT:
		{
			//һ���Զϵ������к��޸���ɾ��
			if (DeleteSoftBreakPoint(ProcessInfo))
			{	
				break;
			}
			//������INT 3�ϵ�
			else 
			{
				printf_s("����Ӳ���ж϶ϵ�: %p\n", ProcessInfo.ExceptionAddress);
				RemoveSoftBreakPoint(ProcessInfo, TRUE, ProcessInfo.ExceptionAddress);//�ڷ���ຯ�����ͳһ�����޸�
				break;
			}
		}
		//����,���ԼĴ����ϵ�
		case EXCEPTION_SINGLE_STEP:
		{
			if (ClearHBreakPoint(ProcessInfo))//�γ�Ӳ���ϵ�
			{//Ӳ���ϵ�
				printf_s("����Ӳ���ϵ�: %p\n", ProcessInfo.ExceptionAddress);
			}
			//�������账��
			//�����ὫCC����һ���Զϵ㣬Ҳ���账��
			break;
		}
		default:
		{
			printf_s("δ�����쳣����(%08X): %p\n", ProcessInfo.ExceptionCode, ProcessInfo.ExceptionAddress);
			ret = FALSE;
			break;
		}
	}
	//�����
	Disassembly(ProcessInfo, ProcessInfo.ExceptionAddress, 10);//����൱ǰ�쳣��ַ
	//��������
	GetCommend(ProcessInfo);

	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
	return ret;
}
