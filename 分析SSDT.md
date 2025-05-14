```版本WinXP (Windows XP SP3)```

# 分析ExitProcess()函数流程


![alt text](ImageFile\ExitProcess_1.png)

跳转到ZwTerminateProcess通过它在调用0x101号的NtTerminateProcess

![alt text](ImageFile\ExitProcess_3.png)

edx会是`KiIntSystemCall`

![alt text](ImageFile\ExitProcess_4.png)
### 中断系统调用

windbg查看int 0x2e中断门
```
0: kd> !idt 2e

Dumping IDT: 8003f400

2e:	805424b1 nt!KiSystemService
```
为KiSystemService函数
函数开头保存环境和切换栈
0: kd> u KiSystemService
```asm
nt!KiSystemService:
805424b1 6a00            push    0
805424b3 55              push    ebp
805424b4 53              push    ebx
805424b5 56              push    esi
805424b6 57              push    edi
805424b7 0fa0            push    fs
805424b9 bb30000000      mov     ebx,30h
805424be 668ee3          mov     fs,bx

```
![alt text](ImageFile\KiSystemService_1.png)

![alt text](ImageFile\KiSystemService_2.png)



![alt text](ImageFile\KiSystemService_3.png)

定义也就是系统描述服务表SSDT和ShadowSSDT
```c++
KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable[NUMBER_SERVICE_TABLES];
KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTableShadow[NUMBER_SERVICE_TABLES];
```

ServiceTable的结构
```c++
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR Base;//函数指针
    PULONG Count;//函数指针数量
    ULONG Limit;
#if defined(_IA64_)
    LONG TableBaseGpOffset;
#endif
    PUCHAR Number;//参数数量
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
```


为解决高频切换的访问内存的频率
使用`KiFastSystemCall`进内核

![alt text](ImageFile\ExitProcess_5.png)



## MSR寄存器 模式指定寄存器
读取和写入msr寄存器
>rdmsr 读取由ECX指定的MSR到EDX:EAX。 </br>
要读取的msr序号放在ecx当中,执行rdmsr得到的值在EDX:EAX当中

>wrmsr 将EDX:EAX中的值写入ECX指定的MSR。</br>
值在EDX:EAX当中,要写入的msr序号放在ecx 然后执行wrmsr

![alt text](ImageFile\msr_reg.png)
使用了3个msr寄存器辅助切换

|Hex|Decimal|Architectural MSR Name / Bit Fields| MSR/Bit Description|Comment|
|-|-|-|-|-|
|174H|372|IA32_SYSENTER_CS |SYSENTER_CS_MSR (R/W) |06_01H|</br>
|175H|373|IA32_SYSENTER_ESP|SYSENTER_ESP_MSR (R/W)|06_01H|</br>
|176H|374|IA32_SYSENTER_EIP|SYSENTER_EIP_MSR (R/W)|06_01H|</br>


## 系统快速调用

系统快速调用有两种:
sysenter/sysexit
syscall/sysret

`KiFastSystemCall`当中使用了sysenter执行并行函数完成后使用sysexit返回

### SYSENTER and SYSEXIT Instructions in IA-32e Mode
>When `SYSENTER` transfers control, the following fields are generated and bits set:</br>
> • Target code segment — Reads non-NULL selector from IA32_SYSENTER_CS.</br>
> • New CS attributes — CS base = 0, CS limit = FFFFFFFFH.</br>
> • Target instruction — Reads 64-bit canonical address from IA32_SYSENTER_EIP.</br>
> • Stack segment — Computed by adding 8 to the value from IA32_SYSENTER_CS.</br>
> • Stack pointer — Reads 64-bit canonical address from IA32_SYSENTER_ESP.</br>
> • New SS attributes — SS base = 0, SS limit = FFFFFFFFH</br>

> When the SYSEXIT instruction transfers control to 64-bit mode user code using REX.W, the following fields are generated and bits set:</br>
> • Target code segment — Computed by adding 32 to the value in IA32_SYSENTER_CS.</br>
> • New CS attributes — L-bit = 1 (go to 64-bit mode).</br>
> • Target instruction — Reads 64-bit canonical address in RDX.</br>
> • Stack segment — Computed by adding 40 to the value of IA32_SYSENTER_CS.</br>

> When SYSEXIT transfers control to compatibility mode user code when the operand size attribute is 32 bits, the following fields are generated and bits set:</br>
> • Target code segment — Computed by adding 16 to the value in IA32_SYSENTER_CS.</br>
> • New CS attributes — L-bit = 0 (go to compatibility mode).</br>
> • Target instruction — Fetch the target instruction from 32-bit address in EDX.</br>
> • Stack segment — Computed by adding 24 to the value in IA32_SYSENTER_CS.</br>
> • Stack pointer — Update ESP from 32-bit address in ECX.</br>

通过代码段和数据段相邻节省寄存器，即
目标代码段-通过在IA32_SYSENTER_CS中的值加上16计算
### Fast System Calls in 64-Bit Mode
>For SYSCALL, the processor saves RFLAGS into R11 and the RIP of the next instruction into RCX; it then gets the privilege-level 0 target code segment, instruction pointer, stack segment, and flags as follows:</br>
> • Target code segment — Reads a non-NULL selector from IA32_STAR[47:32].</br>
> • Target instruction pointer — Reads a 64-bit address from IA32_LSTAR. (The WRMSR instruction ensures that the value of the IA32_LSTAR MSR is canonical.)</br>
> • Stack segment — Computed by adding 8 to the value in IA32_STAR[47:32].</br>
> • Flags — The processor sets RFLAGS to the logical-AND of its current value with the complement of the value in the IA32_FMASK MSR.</br>

>When SYSRET transfers control to 64-bit mode user code using REX.W, the processor gets the privilege level 3 target code segment, instruction pointer, stack segment, and flags as follows:</br>
> • Target code segment — Reads a non-NULL selector from IA32_STAR[63:48] + 16.</br>
> • Target instruction pointer — Copies the value in RCX into RIP.</br>
> • Stack segment — IA32_STAR[63:48] + 8.</br>
> • EFLAGS — Loaded from R11.</br>

> When SYSRET transfers control to 32-bit mode user code using a 32-bit operand size, the processor gets the privilege level 3 target code segment, instruction pointer, stack segment, and flags as follows:</br>
> • Target code segment — Reads a non-NULL selector from IA32_STAR[63:48].</br>
> • Target instruction pointer — Copies the value in ECX into EIP.</br>
> • Stack segment — IA32_STAR[63:48] + 8.</br>
> • EFLAGS — Loaded from R11.</br>


流程ExitProcess => Kernel32.ExitProcess  => ntdll.NtTerminateProcess(101)

Nt是微软为了兼容以前版本将Zw的函数导出套Nt名称实现的</br>
Zw则是通过KiSystemService调用进系统Ring0的Nt函数
![alt text](ImageFile\ZwTerminateProcess.png)

# SSDT 系统服务描述符表 [System Services Descriptor Table]
## KeServiceDescriptorTable SSDT表
>Xp 和Win7 32 位系统中，SSDT 在内核 Ntoskrnl.exe 中导出，直接获取导出符号 KeServiceDescriptorTable。</br>
>通过 `extern "C" PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;`取得
>也可以通过KTHREAD中取得 通过导出函数KeAddSystemServiceTable函数中取得偏移
>
>而在 64 位系统中，SSDT 表并没有在内核 Ntoskrnl.exe 中导出<br>
>Win7 x64 与 Win10 64（Win10低版本）中,通过 __readmsr(0xC0000082) 获取内核函数 KiSystemCall64 的地址<br>
>KiSystemCall64 中调用了 KeServiceDescriptorTable 和 KeServiceDescriptorTableShadow<br>
>win10 高版本中 __readmsr(0xC0000082) 返回 KiSystemCall64Shadow 函数
>>在高版本当中msr在开启内核隔离模式下获取到的是KiSystemCall64Shadow函数地址<br>在未开启内核隔离模式下获取到的是KiSystemCall64函数地址
>


## KeServiceDescriptorTableShadow ShadowSSDT表
SSDT当中缺失UI的函数</br>
当不是UI的程序是给的是SSDT表</br>
当为UI的程序是给的是ShadowSSDT表</br>



ShadowSSDT当中包含SSDT表</br>
而SSDT当中只有SSDT表</br>
```asm
0: kd> dd KeServiceDescriptorTable
8055d700  80505480 00000000 0000011c 805058f4
0: kd> dd KeServiceDescriptorTableShadow
8055d6c0  80505480 00000000 0000011c 805058f4
8055d6d0  bf99d000 00000000 0000029b bf99dd10
```
查看ShadowSSDT需要切换到UI进程查看才能看到映射</br>
ShadowSSDT的api不在ntkernel.sys当中实现,实现位于独立的win32k.sys当中</br>

### 如何获取ShadowSSDT
ShadowSSDT表 和SSDT是相邻的通过SSDT的偏移或增加能得到ShadowSSDT表</br>
KeAddSystemServiceTable函数当中也包含有ShadowSSDT

### 如何获取ShadowSSDT 原始表
win32k.sys会调用ntos内核的KeAddSystemServiceTable这个方法来初始化ShadowSSDT
![alt text](ImageFile\ShadowSSDT_init.png)

使用KeAddSystemServiceTable来初始化ShadowSSDT的。</br>
而且第一个参数就是W32pServiceTable也就是所要找的ShadowSSDT原始函数数组

![alt text](ImageFile\W32pServiceTable.png)

## 如何判断是ShadowSSDT函数 还是 SSDT表的函数

![alt text](ImageFile\SSDTorSSDTShadow.png)


# SSDT HOOK

>思路：</br>
替换SSDT表函数指针</br>
Hook MSR寄存器</br>
InineHook Hook Nt函数</br>
InineHook kiSystemService 或 KifastCallEntry</br>

NtDuplicateObject
ZwDuplicateObject

>早期通过hook OpenProcess 函数或者是ReadProcessMemory/WriterProcessMemory函数对抗</br>
检测是否是要保护的进程或内存区域，如果是直接返回不给予更改</br>
对抗方式:
Ring3调用内核API 直接通过NTDLL导出函数直接调用</br>
如通过调用NtCreateFile打开内核设备</br>
>XP下不检测特权级别可以：</br>
ZwOpenSection->ZwMapViewOfSection</br>
WinHex使用了该漏洞

绕过函数直接手工调用
```asm
__asm {
	mov eax, 101h
	push 0
	push -1
	mov edx, esp
	int 2eh
}

```
>对抗方式:</br>
Hook SSDT表检测

### 实现SSDT hook
获取编号</br>
通过Ring3遍历ntdll模块导出表获取


hook SSDT表项内容解除hook时会有回调函数延迟调用的问题，当旧的函数被释放时会导致蓝屏</br>
简易解决方式:睡眠x秒</br>
进阶解决方式:通过引用计算进入函数时候，增加引用计数，退出函数时减少引用计数</br>
并且使用原子锁保护引用计数操作流程，防止多线程问题</br>
比较时也需要上原子锁保护</br>

同时需要防止自身的迭代调用



### 检测SSTD Hook
简易:通过获取ntkernel.exe的模块比较是否范围内判断
通过未文档化函数遍历模块
```c++
NtQuerySystemInformation/ZwQuerySystemInformation 函数
__kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);
```
函数的枚举值`SYSTEM_INFORMATION_CLASS`即为`SystemInformation`的大小`SystemInformationLength`


>模块范围检测逃逸:</br>
通过ntkernel.exe找到合适的跳板在跳到自己的函数当中</br>

检测InineHook 从文件当中读取代码，重定位修复后与内存当中的做比较，有差异则出问题</br>
或者比较整个PE文件的代码段差异

### 获取SSDT 原始表
来自于ntos内核函数的`KiInitSystem`的`_KiServiceTable`:
![alt text](ImageFile\SSTD_source.png)

可以看见原表内容
![alt text](ImageFile\SSTD_source2.png)

如何取得该表</br>
该表的位于KiInitSystem函数</br>
通过遍历PE的节.text，加上该区块的显著特征取得</br>

>差异对比逃逸方法：</br>
由于KiFastCallEntry函数通过ETHREAD->ServicesTable取得SSDT表</br>
所以修改ETHREAD->ServicesTable的表地址修改为自己的自定义表</br>
通过遍历线程找到所需要保护的进程修改对应的ETHREAD->ServicesTable</br>
其偏移通过PDB符号文件或者函数当中取得</br>


取得KiServiceTable
需要判断内核文件类型

|内核|PAE|多核|
|-|-|-|
|ntoskrnl.exe|N|N|
|ntkrnlmp.exe|N|Y|
|ntkrnlpa.exe|Y|N|
|ntkrpamp.exe|Y|Y|

或者通过</br>
`ZwQuerySystemInformation`函数和`SystemModuleInformation`标识遍历模块</br>
第一个就是当前使用的NT内核

为了防止内存当中的原始表被修改，通过文件取得偏移后再去用偏移+模块基址
尽量在3环完成搜索


攻击对抗时检测到被攻击可以通过制造蓝屏防御分析


### 微软符号解析DIA
DIA SKD 组件

通过创建 IDiaDataSource 接口获取数据源。
```c++
CComPtr<IDiaDataSource> pSource;
hr = CoCreateInstance( CLSID_DiaSource,
                       NULL,
                       CLSCTX_INPROC_SERVER,
                       __uuidof( IDiaDataSource ),
                      (void **) &pSource);

if (FAILED(hr))
{
    Fatal("Could not CoCreate CLSID_DiaSource. Register msdia80.dll." );
}
```

调用 IDiaDataSource::loadDataFromPdb 或 IDiaDataSource::loadDataForExe 以加载调试信息
```c++
wchar_t wszFilename[ _MAX_PATH ];
mbstowcs( wszFilename, szFilename, sizeof( wszFilename )/sizeof( wszFilename[0] ) );
if ( FAILED( pSource->loadDataFromPdb( wszFilename ) ) )
{
    if ( FAILED( pSource->loadDataForExe( wszFilename, NULL, NULL ) ) )
    {
        Fatal( "loadDataFromPdb/Exe" );
    }
}
```

调用 IDiaDataSource::openSession 以打开 IDiaSession，获取对调试信息的访问权限
```c++
CComPtr<IDiaSession> psession;
if ( FAILED( pSource->openSession( &psession ) ) )
{
    Fatal( "openSession" );
}
```

使用 IDiaSession 中的方法来查询数据源中的符号。
```c++
CComPtr<IDiaSymbol> pglobal;
if ( FAILED( psession->get_globalScope( &pglobal) ) )
{
    Fatal( "get_globalScope" );
}
```

使用 IDiaEnum* 接口枚举和扫描调试信息的符号或其他元素。
```c++
CComPtr<IDiaEnumTables> pTables;
if ( FAILED( psession->getEnumTables( &pTables ) ) )
{
    Fatal( "getEnumTables" );
}
CComPtr< IDiaTable > pTable;
while ( SUCCEEDED( hr = pTables->Next( 1, &pTable, &celt ) ) && celt == 1 )
{
    // Do something with each IDiaTable.
}
```

