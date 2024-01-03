# 系统调用
WIndows平台下R3（用户态）切换到R0（内核态）系统调用 由一条CPU指令完成：syscall
系统调用主要分为3种形式：

-Int 2EH 

-x86的 sysenter  (sysenter/sysexit 一对配套指令用于快速在R3和R0之间转换的指令）

-x64的 syscall   (syscall/sysret 一对配套指令用于快速在R3和R0之间转换的指令)


## Syscall指令基本流程：


1> 把 SYSCALL 的下一条指令保存到 RCX<br>
2> 处理器会把 RFLAGS 保存到 R11<br>
3> 目标指令指针 — 从 IA32_LSTAR 读取 64 位的地址<br>
4> 状态标志 — 把 IA32_FMASK MSR 中的值按位取反后，与当前 RFLAGS 进行逻辑与得到<br>
5> IA32_STAR[47:32] MSR的值赋予CS段描述符并设置RPL特权请求级别为0<br>
6> 设置对应CS的段描述符

==============================================================
#### 伪码（来自Intel手册Vol. 2B 4-689）

~~~~
IF (CS.L ≠ 1 ) or (IA32_EFER.LMA ≠ 1) or (IA32_EFER.SCE ≠ 1)
(* Not in 64-Bit Mode or SYSCALL/SYSRET not enabled in IA32_EFER *)
THEN #UD;
FI;
RCX := RIP; (* Will contain address of next instruction *)
RIP := IA32_LSTAR;
R11 := RFLAGS;
RFLAGS := RFLAGS AND NOT(IA32_FMASK);
CS.Selector := IA32_STAR[47:32] AND FFFCH (* Operating system provides CS; RPL forced to 0 *)
(* Set rest of CS to a fixed value *)
CS.Base := 0; (* Flat segment *)
CS.Limit := FFFFFH; (* With 4-KByte granularity, implies a 4-GByte limit *)
CS.Type := 11; (* Execute/read code, accessed *)
CS.S := 1;
CS.DPL := 0;
CS.P := 1;
CS.L := 1; (* Entry is to 64-bit mode *)
CS.D := 0; (* Required if CS.L = 1 *)
CS.G := 1; (* 4-KByte granularity *)
~~~~

#### Windbg读取的 IA32_FMASK[C0000084H] MSR寄存器
~~~~
[来源Intel Vol. 4 2-61; Table 2-2. IA-32 Architectural MSRs (Contd.)]

kd> rdmsr C0000084H
msr[c0000084] = 00000000`00004700

kd> .formats 00000000`00004700
Evaluate expression:
  Hex:     00000000`00004700
  Decimal: 18176
  Decimal (unsigned) : 18176
  Octal:   0000000000000000043400
  Binary:  00000000 00000000 00000000 00000000 00000000 00000000 01000111 00000000
  Chars:   ......G.
  Time:    Thu Jan  1 13:02:56 1970
  Float:   low 2.547e-041 high 0
  Double:  8.98014e-320

取反后是 FFFFFFFF`FFFFB8FF,也就是对应[RFLAG寄存器]的TF、IF、DF、NT位设置为零

TF标志位:陷阱标志（Trap flag）是标志寄存器的第8位，当其被设置时将开启单步调试模式。在其被设置的情况下，每个指令被执行后都将产生一个调试异常，以便于观察指令执行后的情况。

IF标志位:中断标志（Interrupt flag）是标志寄存器的第9位，当其被设置时表示CPU可响应可屏蔽中断（maskable interrupt）。

DF标志位:IF标志位位于标志寄存器第9位，名称为方向标志位。

NT标志位:嵌套任务（Nested task flag）是标志寄存器的第14位，用于控制中断返回指令IRET的执行方式。
若被设置则将通过中断的方式执行返回，否则通过常规的堆栈的方式执行。在执行CALL指令、中断或异常处理时，处理器将会设置该标志。
~~~~

==============================================================




## 内核接管流程

R3调用syscall后在内核执行的函数 <font color=#FFFAAA>KiSystemCall64</font> (开启页表隔离KPTI后是KiSystemCall64Shadow)

基本流程：<br>
1->切换GS指向KPCR(CPU控制区 Processor Control Region)<br>
2->用户栈切换到内核栈<br>
3->STAC指令将SMAP关闭(STAC指令相当于Set AC 用于设置AC标志位，能暂时解除系统的一些保护，包括SMAP保护)<br>
4->保存用户线程Context到_KTRAP_FRAME<br>
5->根据EAX内容算出用户指定的内核态例程地址<br>
6->将用户栈上的参数复制到内核栈<br>
7->调用内核函数<br>
8->执行用户态APC<br>
9->将函数返回值写入_KTRAP_FRAME.RAX,恢复用户态Context,使用Sysret指令返回用户态执行

### 相关要点补充
<details>
<summary>AC位影响SMAP相关描述</summary>
<pre><code>
==============================================================

#### Intel(Vol. 3A 4-34)
~~~~
— Data reads from user-mode pages.
Access rights depend on the value of CR4. SMAP:
• If CR4. SMAP = 0, data may be read from any user-mode address with a protection key for which read access is permitted.
• If CR4. SMAP = 1, access rights depend on the value of EFLAGS. AC and whether the access is implicit or
explicit:
— If EFLAGS. AC = 1 and the access is explicit, data may be read from any user-mode address with a protection key for which read access is permitted.
— If EFLAGS. AC = 0 or the access is implicit, data may not be read from any user-mode address
~~~~

大致意思:

—如果是EFLAGS.AC = 1并且访问是显式的，数据可以从任何具有允许读访问的保护键的用户模式地址读取。

—如果是EFLAGS.AC = 0或访问是隐式的，则不能从任何用户模式地址读取数据

==============================================================
</code></pre>
</details>

<details>
<summary>FS/GS寄存器</summary>
<pre><code>
==============================================================

3环FS/GS指向_TEB<br>
0环FS/GS指向_KPCR

在64位系统下
gs:[0x30] 指向TEB
gs:[0x60] 指向PEB


==============================================================
</code></pre>
</details>


<details>
<summary>_KPCR结构解析</summary>
<pre><code>
==============================================================

~~~~
//0x178 bytes (sizeof)
struct _KPCR
{
    union
    {
        struct _NT_TIB NtTib;                                               //0x0   保存CPU常用的信息(比如异常处理函数链表、栈大小空间限制)
        struct
        {
            union _KGDTENTRY64* GdtBase;                                    //0x0
            struct _KTSS64* TssBase;                                        //0x8
            ULONGLONG UserRsp;                                              //0x10  指向自身,类似C++的this指针一样，方便编程
            struct _KPCR* Self;                                             //0x18
            struct _KPRCB* CurrentPrcb;                                     //0x20  指向 PrcbData : _KPRCB 结构体，该结构体为_KPCR的拓展，这么做(而不是使用偏移)是为了当其地址改变时也能正确找到
            struct _KSPIN_LOCK_QUEUE* LockArray;                            //0x28
            VOID* Used_Self;                                                //0x30
        };
    };
    union _KIDTENTRY64* IdtBase;                                            //0x38  IDT表 一个CPU一套
    ULONGLONG Unused[2];                                                    //0x40
    UCHAR Irql;                                                             //0x50  IRQL中断等级
    UCHAR SecondLevelCacheAssociativity;                                    //0x51
    UCHAR ObsoleteNumber;                                                   //0x52  当前CPU编号
    UCHAR Fill0;                                                            //0x53
    ULONG Unused0[3];                                                       //0x54
    USHORT MajorVersion;                                                    //0x60  版本细节
    USHORT MinorVersion;                                                    //0x62  版本细节
    ULONG StallScaleFactor;                                                 //0x64
    VOID* Unused1[3];                                                       //0x68
    ULONG KernelReserved[15];                                               //0x80
    ULONG SecondLevelCacheSize;                                             //0xbc
    ULONG HalReserved[16];                                                  //0xc0
    ULONG Unused2;                                                          //0x100
    VOID* KdVersionBlock;                                                   //0x108 仅在0号CPU下有值
    VOID* Unused3;                                                          //0x110
    ULONG PcrAlign1[24];                                                    //0x118
}; 

//0x38 bytes (sizeof)
struct _NT_TIB
{
    struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;                   //0x0   异常链表
    VOID* StackBase;                                                        //0x8   栈基址
    VOID* StackLimit;                                                       //0x10  栈大小显示
    VOID* SubSystemTib;                                                     //0x18
    union
    {
        VOID* FiberData;                                                    //0x20
        ULONG Version;                                                      //0x20
    };
    VOID* ArbitraryUserPointer;                                             //0x28
    struct _NT_TIB* Self;                                                   //0x30  this指针指向结构体自己
}; 

~~~~

==============================================================
</code></pre>
</details>

<details>
<summary>_KPRCB结构解析</summary>
<pre><code>
==============================================================
起始一般位于_KPCR表结尾,属于_KPCR的拓展表

~~~~
//0x700 bytes (sizeof)
struct _KPRCB
{
    ULONG MxCsr;                                                            //0x0
    UCHAR LegacyNumber;                                                     //0x4
    UCHAR ReservedMustBeZero;                                               //0x5
    UCHAR InterruptRequest;                                                 //0x6
    UCHAR IdleHalt;                                                         //0x7
    struct _KTHREAD* CurrentThread;                                         //0x8   当前运行线程
    struct _KTHREAD* NextThread;                                            //0x10  下一个要切换的线程
    struct _KTHREAD* IdleThread;                                            //0x18  系统空闲进程
    UCHAR NestingLevel;                                                     //0x20
    UCHAR ClockOwner;                                                       //0x21
    union
    {
        UCHAR PendingTickFlags;                                             //0x22
        struct
        {
            UCHAR PendingTick:1;                                            //0x22
            UCHAR PendingBackupTick:1;                                      //0x22
        };
    };
    UCHAR IdleState;                                                        //0x23
    ULONG Number;                                                           //0x24
    ULONGLONG RspBase;                                                      //0x28
    ULONGLONG PrcbLock;                                                     //0x30
    CHAR* PriorityState;                                                    //0x38
    CHAR CpuType;                                                           //0x40
    CHAR CpuID;                                                             //0x41
    union
    {
        USHORT CpuStep;                                                     //0x42
        struct
        {
            UCHAR CpuStepping;                                              //0x42
            UCHAR CpuModel;                                                 //0x43
        };
    };
    ULONG MHz;                                                              //0x44
    ULONGLONG HalReserved[8];                                               //0x48
    USHORT MinorVersion;                                                    //0x88
    USHORT MajorVersion;                                                    //0x8a
    UCHAR BuildType;                                                        //0x8c
    UCHAR CpuVendor;                                                        //0x8d
    UCHAR LegacyCoresPerPhysicalProcessor;                                  //0x8e
    UCHAR LegacyLogicalProcessorsPerCore;                                   //0x8f
    ULONGLONG TscFrequency;                                                 //0x90
    ULONG CoresPerPhysicalProcessor;                                        //0x98
    ULONG LogicalProcessorsPerCore;                                         //0x9c
    ULONGLONG PrcbPad04[4];                                                 //0xa0
    struct _KNODE* ParentNode;                                              //0xc0
    ULONGLONG GroupSetMember;                                               //0xc8
    UCHAR Group;                                                            //0xd0
    UCHAR GroupIndex;                                                       //0xd1
    UCHAR PrcbPad05[2];                                                     //0xd2
    ULONG InitialApicId;                                                    //0xd4
    ULONG ScbOffset;                                                        //0xd8
    ULONG ApicMask;                                                         //0xdc
    VOID* AcpiReserved;                                                     //0xe0
    ULONG CFlushSize;                                                       //0xe8
    ULONGLONG PrcbPad11[2];                                                 //0xf0
    struct _KPROCESSOR_STATE ProcessorState;                                //0x100
    struct _XSAVE_AREA_HEADER* ExtendedSupervisorState;                     //0x6c0
    ULONG ProcessorSignature;                                               //0x6c8
    ULONG ProcessorFlags;                                                   //0x6cc
    ULONGLONG PrcbPad12a;                                                   //0x6d0
    ULONGLONG PrcbPad12[3];                                                 //0x6d8
}; 
~~~~
==============================================================
</code></pre>
</details>



<details>
<summary>RIP相对寻址(Rip_Relative_Addressing)</summary>
<pre><code>


==============================================================

#### 原文介绍(RIP-Relative Addressing For Intel Vol. 2A 2-12)

|Legacy<br>Prefixes|REX<br>Prefix|Opcode|ModR/M|SIB|Displacement|Immediate|
|:----:|:----:|:----:|:----:|:----:|:----:|:----:|
|Grp 1, Grp 2<br> Grp 3, Grp 4<br>(optional)|(optional)|1-,2-,or<br>3-byte<br>opcode|1 byte<br>(if required)|1 byte<br>(if required)|Address<br>displacement of<br>1, 2, or 4 bytes|Immediate data<br>of 1, 2, or 4<br>bytes or none|


<table>
    <tr>
        <td>Legacy<br>Prefixes</td> 
        <td>REX<br>Prefix</td> 
        <td>Opcode</td>
        <td>ModR/M</td> 
        <td>SIB</td> 
        <td>Displacement</td> 
        <td>Immediate</td> 
   </tr>
    <tr>
  		<td>Grp 1, Grp 2<br> Grp 3, Grp 4<br>(optional)</td> 
        <td>(optional)</td> 
        <td>1-,2-,or<br>3-byte<br>opcode</td>
        <td>1 byte<br>(if required)</td> 
        <td>1 byte<br>(if required)</td>
        <td>Address<br>displacement of<br>1, 2, or 4 bytes</td>
        <td>Immediate data<br>of 1, 2, or 4<br>bytes or none</td>
    </tr>
</table>

~~~~
[2.2.1.5 Immediates] 
In 64-bit mode, the instruction’s default operation size is 32 bits. Use of the REX.R prefix permits access to additional
registers (R8-R15). Use of the REX.W prefix promotes operation to 64 bits. See the summary chart at the
beginning of this section for encoding data and limits.

在64位下仍使用32位操作数，REX.R扩展寄存器，REX.W扩展指令。

~~~~

==============================================================
</code></pre>
</details>


#### IDA源码(KiSystemCall64)
~~~~
.text:000000014040EF00 swapgs                                  ; 切换GS使GS：0指向_KPCR
.text:000000014040EF03 mov     gs:_KPCR.___u0.__s1.UserRsp, rsp
.text:000000014040EF0C mov     rsp, gs:_KPCR.Prcb.RspBase      ; 切换到内核态
.text:000000014040EF15 push    2Bh ; '+'                       ; 内核栈上构造Trap_Frame 从_KTRAP_FRAME.SegSs+0x188开始压栈
.text:000000014040EF17 push    gs:_KPCR.___u0.__s1.UserRsp
.text:000000014040EF1F push    r11                             ; R11 =RFLAGS (syscall)
.text:000000014040EF21 push    33h ; '3'
.text:000000014040EF23 push    rcx                             ; RCX=UserRip(syscall)
.text:000000014040EF24 mov     rcx, r10                        ; R10=Rcx (Ntdll.dll)
.text:000000014040EF27 sub     rsp, 8                          ; skip ExceptionFram and ErrorCode
.text:000000014040EF2B push    rbp                             ; 保存 userRBP 到 _KTRAP_FRAME.Rbp(+0x158)
.text:000000014040EF2C sub     rsp, 158h                       ; 提升栈顶指针到_KTRAP_FRAME顶部
.text:000000014040EF33 lea     rbp, [rsp+190h+var_110]         ; RBP->_KTRAP_FRAME.Xmm1(0x80)
.text:000000014040EF3B mov     [rbp+0C0h], rbx                 ; _KTRAP_FRAME.Rbx
.text:000000014040EF42 mov     [rbp+0C8h], rdi                 ; _KTRAP_FRAME.Rdi
.text:000000014040EF49 mov     [rbp+0D0h], rsi                 ; _KTRAP_FRAME.Rsi
.text:000000014040EF50 test    byte ptr cs:KeSmapEnabled, 0FFh ; KeSmapEnabled标志位，是否开启Smap该位的作用是阻止处于内核权限的CPU读取或写入用户代码
.text:000000014040EF57 jz      short loc_14040EF65             ; _KTRAP_FRAME.Rax
.text:000000014040EF57
.text:000000014040EF59 test    byte ptr [rbp+0F0h], 1          ; 判断执行syscall前的特权模式
.text:000000014040EF60 jz      short loc_14040EF65             ; 若为内核态则不必关闭SMAP保护 SMAP(Supervisor Mode Access Prevention，管理模式访问保护)和SMEP(Supervisor Mode Execution Prevention，管理模式执行保护)
.text:000000014040EF60
.text:000000014040EF62 stac                                    ; Set AC Flag 允许在SMAP激活的情况下，在内核态访问用户态数据

.text:000000014040EF65 loc_14040EF65:                          ; CODE XREF: KiSystemCall64+57↑j
.text:000000014040EF65                                         ; KiSystemCall64+60↑j
.text:000000014040EF65 mov     [rbp-50h], rax                  ; _KTRAP_FRAME.Rax
.text:000000014040EF69 mov     [rbp-48h], rcx                  ; _KTRAP_FRAME.Rcx
.text:000000014040EF6D mov     [rbp-40h], rdx                  ; _KTRAP_FRAME.Rdx
.text:000000014040EF71 mov     rcx, gs:_KPCR.Prcb.CurrentThread
.text:000000014040EF7A mov     rcx, [rcx+_KTHREAD.Process]
.text:000000014040EF81 mov     rcx, [rcx+_EPROCESS.SecurityDomain]
.text:000000014040EF88 mov     gs:_KPCR.Prcb.___u42.PrcbPad11, rcx
.text:000000014040EF91 mov     cl, byte ptr gs:_KPCR.Prcb.___u47.PrcbPad12a
.text:000000014040EF99 mov     byte ptr gs:_KPCR.Prcb.___u47.PrcbPad12a+1, cl
.text:000000014040EFA1 mov     cl, byte ptr gs:_KPCR.Prcb.___u42.PrcbPad11+8
.text:000000014040EFA9 mov     byte ptr gs:_KPCR.Prcb.___u47.PrcbPad12a+2, cl
.text:000000014040EFB1 movzx   eax, byte ptr gs:_KPCR.Prcb.___u42.PrcbPad11+0Bh
.text:000000014040EFBA cmp     byte ptr gs:_KPCR.Prcb.___u42.PrcbPad11+0Ah, al
.text:000000014040EFC2 jz      short loc_14040EFD5
.text:000000014040EFC2
.text:000000014040EFC4 mov     byte ptr gs:_KPCR.Prcb.___u42.PrcbPad11+0Ah, al
.text:000000014040EFCC mov     ecx, 48h ; 'H'                  ; IA32_SPEC_CTRL MSR分支预测相关
.text:000000014040EFD1 xor     edx, edx
.text:000000014040EFD3 wrmsr                                   ; MSR[ECX]=EDX:EAX 写模式定义寄存器。
.text:000000014040EFD3                                         ; 对于WRMSR指令，把要写入的信息存入(EDX：EAX)中
.text:000000014040EFD3                                         ; 执行写指令后，即可将相应的信息存入ECX指定的MSR中
.text:000000014040EFD3
.text:000000014040EFD5
.text:000000014040EFD5 loc_14040EFD5:                          ; CODE XREF: KiSystemCall64+C2↑j
.text:000000014040EFD5 movzx   edx, byte ptr gs:_KPCR.Prcb.___u42.PrcbPad11+8
.text:000000014040EFDE test    edx, 8
.text:000000014040EFE4 jz      short loc_14040EFFD             ; 若CPU存在可以干预分支预测的功能
.text:000000014040EFE4                                         ; 则不必使用浪费性能的软件补丁解决漏洞
.text:000000014040EFE4
.text:000000014040EFE6 mov     eax, 1
.text:000000014040EFEB xor     edx, edx
.text:000000014040EFED mov     ecx, 49h ; 'I'                  ; IA32_PRED_CMD MSR
.text:000000014040EFF2 wrmsr                                   ; MSR[ECX]=EDX:EAX
.text:000000014040EFF4 movzx   edx, byte ptr gs:_KPCR.Prcb.___u42.PrcbPad11+8


......分支预测相关的东西


.text:000000014040F12E loc_14040F12E:                          ; CODE XREF: KiSystemCall64+103↑j
.text:000000014040F12E lfence                                  ; 禁止CPU对后面的指令预测执行
.text:000000014040F131 mov     byte ptr gs:_KPCR.Prcb.___u47.PrcbPad12a+3, 0
.text:000000014040F131
.text:000000014040F13A
.text:000000014040F13A KiSystemServiceUser:                    ; CODE XREF: KiSystemService+231↑j
.text:000000014040F13A                                         ; KiSystemCall64Shadow+252↓j
.text:000000014040F13A mov     [rbp+(_KTRAP_FRAME.ExceptionActive-80h)], 2 ; _KTRAP_FRAME.ExceptionActive
.text:000000014040F13E mov     rbx, gs:_KPCR.Prcb.CurrentThread
.text:000000014040F147 prefetchw byte ptr [rbx+_KTHREAD.TrapFrame] ; 预写时将数据预取到缓存中
.text:000000014040F14E stmxcsr dword ptr [rbp-54h]             ; _KTRAP_FRAME.MxCsr STMXCSR指令将MXCSR寄存器状态保存到存储器中
.text:000000014040F152 ldmxcsr dword ptr gs:180h               ; LDMXCSR指令从存储器中加载到MXCSR寄存器
.text:000000014040F15B cmp     [rbx+_KTHREAD.Header.___u0.__s2.Reserved1], 0
.text:000000014040F15F mov     word ptr [rbp+80h], 0           ; _KTRAP_FRAME.ExceptionFrame
.text:000000014040F168 jz      loc_14040F23E                   ; _KTRAP_FRAME.RAX Trap_Frame取出用户态数据

~~~~

