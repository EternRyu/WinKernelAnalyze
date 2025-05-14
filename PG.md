
### PatchGuard KPP

PG的代码是异或加密的，运行一行解密一行，并且蓝屏错误给出的堆栈信息也是被加密的</br>
低版本当中的PG代码的启动通过异常处理当中启动


### 如何调试PG
开机时候先不连接调试器，让PG检测没有调试器链接得以启动


### 如何找到PG代码
特征:</br>
旧版本当中PG代码的PDB符号被删除</br>
通过IDA解析后找从无名函数当中找到</br>
其次因为要进行检测操作,所以其函数的代码量必然不小</br>

![alt text](ImageFile\PG_FUN_NAME.png)

在新版本当中给了一个假名称


KiFilterFiberContext当中调用了PG初始化代码
![alt text](ImageFile\KiFilterFiberContext.png)

KeInitAmd64SpecificState当中使用了异常进行调用
判断是否是调试状态，如果不是调试状态产生除零异常
![alt text](ImageFile\KeInitAmd64SpecificState_fast.png)

异常处理当中对PGInit的上一级函数KiFilterFiberContext进行调用
![alt text](ImageFile\KeInitAmd64SpecificState.png)

PG调用流程

>KiSystemStartup</br>
>->KiInitializeKernel</br>
>->InitBootProcessor</br>
>->PsInitSystem</br>
>->PspInitPhase0</br>
>->Phase1Initialization</br>
>->Phase1InitializationDiscard</br>
>->KeInitAmd64SpecificState</br>
>->KiFilterFiberContext</br>
>->PGInit </br>

### PG代码
PG函数头部检测是否是安全模式，是直接退出PG初始化
![alt text](ImageFile\PG_HEADER.png)

# 绕过PG
1.对ntos文件打补丁，需要对winload文件的签名校验修改</br>
2.直接修改系统,有线程检测ntos文件如果被修改到时间会进行还原</br>

### 静态过PG
对ntos文件打补丁，调用PGInit前的函数进行补丁，通过创建新的启动选项绕过签名验证</br>
或者找到SeValidateImageData函数当中的g_CiEnabled全局变量,使驱动签名验证关闭

### 动态过PG
内存当中定位PG代码

特征：</br>
1.代码在堆当中运行</br>
2.堆的页属性是可执行的</br>
3.堆的大小非常大，需要容纳下PG的代码</br>


代码思路：
通过ZwQuerySystemInformation的SystemBigPoolInformation选项找到内存池</br>
通过堆PTE的(NX=0)，产生缺页异常，通过对IDT缺页异常函数的hook，并检测异常地址内是否有PG 的异或解密

PG Win7x64下的代码
```asm
INIT:0000000140554DE0                         CmpAppendDllSection proc near           ; DATA XREF: .pdata:000000014029AFC4↑o
INIT:0000000140554DE0                                                                 ; PGinit+1653↑o
INIT:0000000140554DE0                                         db      2Eh
INIT:0000000140554DE0 2E 48 31 11                             xor     [rcx], rdx
INIT:0000000140554DE4 48 31 51 08                             xor     [rcx+8], rdx
INIT:0000000140554DE8 48 31 51 10                             xor     [rcx+10h], rdx
INIT:0000000140554DEC 48 31 51 18                             xor     [rcx+18h], rdx
INIT:0000000140554DF0 48 31 51 20                             xor     [rcx+20h], rdx
INIT:0000000140554DF4 48 31 51 28                             xor     [rcx+28h], rdx
INIT:0000000140554DF8 48 31 51 30                             xor     [rcx+30h], rdx
INIT:0000000140554DFC 48 31 51 38                             xor     [rcx+38h], rdx
INIT:0000000140554E00 48 31 51 40                             xor     [rcx+40h], rdx
INIT:0000000140554E04 48 31 51 48                             xor     [rcx+48h], rdx
INIT:0000000140554E08 48 31 51 50                             xor     [rcx+50h], rdx
INIT:0000000140554E0C 48 31 51 58                             xor     [rcx+58h], rdx
INIT:0000000140554E10 48 31 51 60                             xor     [rcx+60h], rdx
INIT:0000000140554E14 48 31 51 68                             xor     [rcx+68h], rdx
INIT:0000000140554E18 48 31 51 70                             xor     [rcx+70h], rdx
INIT:0000000140554E1C 48 31 51 78                             xor     [rcx+78h], rdx
INIT:0000000140554E20 48 31 91 80 00 00 00                    xor     [rcx+80h], rdx
INIT:0000000140554E27 48 31 91 88 00 00 00                    xor     [rcx+88h], rdx
INIT:0000000140554E2E 48 31 91 90 00 00 00                    xor     [rcx+90h], rdx
INIT:0000000140554E35 48 31 91 98 00 00 00                    xor     [rcx+98h], rdx
INIT:0000000140554E3C 48 31 91 A0 00 00 00                    xor     [rcx+0A0h], rdx
INIT:0000000140554E43 48 31 91 A8 00 00 00                    xor     [rcx+0A8h], rdx
INIT:0000000140554E4A 48 31 91 B0 00 00 00                    xor     [rcx+0B0h], rdx
INIT:0000000140554E51 48 31 91 B8 00 00 00                    xor     [rcx+0B8h], rdx
INIT:0000000140554E58 48 31 91 C0 00 00 00                    xor     [rcx+0C0h], rdx
INIT:0000000140554E5F 31 11                                   xor     [rcx], edx
INIT:0000000140554E61 48 8B C2                                mov     rax, rdx
INIT:0000000140554E64 48 8B D1                                mov     rdx, rcx
INIT:0000000140554E67 8B 8A C4 00 00 00                       mov     ecx, [rdx+0C4h]
INIT:0000000140554E6D
INIT:0000000140554E6D                         loc_140554E6D:                          ; CODE XREF: CmpAppendDllSection+98↓j
INIT:0000000140554E6D 48 31 84 CA C0 00 00 00                 xor     [rdx+rcx*8+0C0h], rax
INIT:0000000140554E75 48 D3 C8                                ror     rax, cl
INIT:0000000140554E78 E2 F3                                   loop    loc_140554E6D
INIT:0000000140554E7A 8B 82 88 02 00 00                       mov     eax, [rdx+288h]
INIT:0000000140554E80 48 03 C2                                add     rax, rdx
INIT:0000000140554E83 48 83 EC 28                             sub     rsp, 28h
INIT:0000000140554E87 FF D0                                   call    rax
INIT:0000000140554E89 48 83 C4 28                             add     rsp, 28h
INIT:0000000140554E8D 4C 8B 80 E8 00 00 00                    mov     r8, [rax+0E8h]
INIT:0000000140554E94 48 8D 88 40 02 00 00                    lea     rcx, [rax+240h]
```

PG的检测代码在win7 x64下
```asm
INITKDBG:00000001401D3008                         PGCheck         proc near               ; DATA XREF: .pdata:000000014028408C↓o
INITKDBG:00000001401D3008                                                                 ; PGinit+B7↓o
INITKDBG:00000001401D3008
INITKDBG:00000001401D3008                         var_4E0         = qword ptr -4E0h
INITKDBG:00000001401D3008                         var_4D8         = byte ptr -4D8h
INITKDBG:00000001401D3008                         var_4D6         = qword ptr -4D6h
INITKDBG:00000001401D3008                         var_4C8         = byte ptr -4C8h
INITKDBG:00000001401D3008                         var_460         = byte ptr -460h
INITKDBG:00000001401D3008                         var_450         = xmmword ptr -450h
INITKDBG:00000001401D3008                         var_440         = xmmword ptr -440h
INITKDBG:00000001401D3008                         var_340         = xmmword ptr -340h
INITKDBG:00000001401D3008                         var_2C0         = qword ptr -2C0h
INITKDBG:00000001401D3008                         var_2B8         = qword ptr -2B8h
INITKDBG:00000001401D3008                         var_2B0         = qword ptr -2B0h
INITKDBG:00000001401D3008                         var_20          = byte ptr -20h
INITKDBG:00000001401D3008
INITKDBG:00000001401D3008 48 8B C4                                mov     rax, rsp
INITKDBG:00000001401D300B 48 89 58 08                             mov     [rax+8], rbx
INITKDBG:00000001401D300F 48 89 70 10                             mov     [rax+10h], rsi
INITKDBG:00000001401D3013 48 89 78 18                             mov     [rax+18h], rdi
INITKDBG:00000001401D3017 55                                      push    rbp
INITKDBG:00000001401D3018 41 54                                   push    r12
INITKDBG:00000001401D301A 41 55                                   push    r13
INITKDBG:00000001401D301C 41 56                                   push    r14
INITKDBG:00000001401D301E 41 57                                   push    r15
INITKDBG:00000001401D3020 48 81 EC C0 02 00 00                    sub     rsp, 2C0h
INITKDBG:00000001401D3027 48 8D A8 D8 FD FF FF                    lea     rbp, [rax-228h]
INITKDBG:00000001401D302E 48 83 E5 80                             and     rbp, 0FFFFFFFFFFFFFF80h
INITKDBG:00000001401D3032 48 8B DA                                mov     rbx, rdx
INITKDBG:00000001401D3035 BA 26 00 00 00                          mov     edx, 26h ; '&'
INITKDBG:00000001401D303A 41 B8 30 01 00 00                       mov     r8d, 130h
INITKDBG:00000001401D3040 48 8D 85 80 00 00 00                    lea     rax, [rbp+4E0h+var_460]
INITKDBG:00000001401D3047 45 33 FF                                xor     r15d, r15d
INITKDBG:00000001401D304A 41 BE F8 FF FF FF                       mov     r14d, 0FFFFFFF8h
INITKDBG:00000001401D3050 44 8D 62 DB                             lea     r12d, [rdx-25h]
INITKDBG:00000001401D3054 41 8B C8                                mov     ecx, r8d
INITKDBG:00000001401D3057
INITKDBG:00000001401D3057                         loc_1401D3057:                          ; CODE XREF: PGCheck+5C↓j
INITKDBG:00000001401D3057 4C 89 38                                mov     [rax], r15
```