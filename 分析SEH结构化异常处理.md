# SEH Structure Exception Handler 结构化异常处理

当有中断或异常发生时，CPU 会通过中断描述符（IDT Interrupt Descriptor Table）来寻找处理函数</br>
IDT 的位置和长度是由 IDTR 寄存器描述的</br>

### 用户态下
异常处理器处理顺序流程：
1. 交给调试器(进程必须被调试)
2. 执行VEH
3. 执行SEH
4. TopLevelEH(进程被调试时不会被执行) 顶层异常处理
5. 交给调试器(再次交给调试器)
6. 调用异常端口通知csrss.exe 系统调用 ExitProcess 函数来终结程序(在终结程序之前，系统会再次调用发生异常的线程中的所有异常处理过程，这是线程异常处理过程所获得的清理未释放资源的最后机会)

SEH是基于线程栈的异常处理机制，所以它只能处理自己线程的异常</br>
fs:[0]是TEB的 _NT_TIB64 NtTib->ExceptionList


![alt text](ImageFile\SEH_Stack.png)

为了让用户态的异常处理程序能够访问与异常相关的数据，操作系统必须把与本次异常相关联的 EXCEPTION_RECORD 结构和 CONTEXT 结构放到用户态栈

```c++
//0x10 bytes (sizeof)
struct _EXCEPTION_POINTERS
{
    struct _EXCEPTION_RECORD* ExceptionRecord;指向 EXCEPTION_RECORD 结构    //0x0
    struct _CONTEXT* ContextRecord;           指向 CONTEXT 结构             //0x8
}; 

```

### 内核态下
(异常处理函数会进一步调用系统内核的 nt!KiDispatchException 函数来处理异常)
当 PreviousMode 为 KernelMode 时，表示是内核模式下产生的异常,此时 KiDispatchException 会按以下步骤分发异常
1. 检测当前系统是否正在被内核调试器调试。如果内核调试器不存在，就跳过本步骤。
2. 如果不存在内核调试器，或者在第1次处理机会出现时调试器选择不处理该异常，系统就会调用 nt!RtIDispatchException 函数，根据线程注册的结构化异常处理(Structured Exception Handling,SEH )过程来处理该异常
3. 如果 nt!RtIDispatchException 函数没有处理该异常,系统会给调试器第2次处理机会( SecondChance )，此时调试器可以再次取得对异常的处理权
4. 如果不存在内核调试器，或者在第2次机会调试器仍不处理，系统就认为在这种情况下不能继续运行了。为了避免引起更加严重的、不可预知的错误，系统会直接调用 KeBugCheckEx 产生一个错误码为“KERNEL_MODE_EXCEPTION_NOT_HANDLED”(其值为 0x0000008E )的 BSOD (蓝屏错误)

## 异常发生
当有中断或异常发生时，CPU 会根据中断类型号（异常也视为一种中断）转而执行对应的中断处理程序,
如中断号03对应于一个断点异常，当该异常发生时,CPU就会执行 nt!KiTrap03 函数来处理该异常。各个异常处理函数除了针对本异常的特定处理之外,通常会将异常信息进行封装，以便进行后续处理。

封装的内容主要有两部分：一部分是异常记录，包含本次异常的信息,该结构定义如下
~~~c++
//0x98 bytes (sizeof)
struct _EXCEPTION_RECORD64
{
    LONG ExceptionCode;      异常代码                                        //0x0
    ULONG ExceptionFlags;    异常标志                                        //0x4
    ULONGLONG ExceptionRecord;  指向另一个_EXCEPTION_RECORD64指针            //0x8
    ULONGLONG ExceptionAddress; 异常发生地址                                 //0x10
    ULONG NumberParameters;  ExceptionInformation含有的元素数目              //0x18
    ULONG __unusedAlignment;                                                //0x1c
    ULONGLONG ExceptionInformation[15]; 附加信息                            //0x20
}; 
~~~

另一部分被封装的内容称为陷阱帧，它精确描述了发生异常时线程的状态( Windows 的任务调度是基于线程的)在不同的平台上（Intel x86/x64、MIPS、Alpha 和 PowerPC 处理器等）有不同的定义
<details> 
<summary><font size="4" color="orange">_KTRAP_FRAME结构</font></summary> 
<pre><code class="language-cpp">

~~~c++
//0x190 bytes (sizeof)
struct _KTRAP_FRAME
{
    ULONGLONG P1Home;                                                       //0x0
    ULONGLONG P2Home;                                                       //0x8
    ULONGLONG P3Home;                                                       //0x10
    ULONGLONG P4Home;                                                       //0x18
    ULONGLONG P5;                                                           //0x20
    union
    {
        CHAR PreviousMode;                                                  //0x28
        UCHAR InterruptRetpolineState;                                      //0x28
    };
    UCHAR PreviousIrql;                                                     //0x29
    union
    {
        UCHAR FaultIndicator;                                               //0x2a
        UCHAR NmiMsrIbrs;                                                   //0x2a
    };
    UCHAR ExceptionActive;                                                  //0x2b
    ULONG MxCsr;                                                            //0x2c
    ULONGLONG Rax;                                                          //0x30
    ULONGLONG Rcx;                                                          //0x38
    ULONGLONG Rdx;                                                          //0x40
    ULONGLONG R8;                                                           //0x48
    ULONGLONG R9;                                                           //0x50
    ULONGLONG R10;                                                          //0x58
    ULONGLONG R11;                                                          //0x60
    union
    {
        ULONGLONG GsBase;                                                   //0x68
        ULONGLONG GsSwap;                                                   //0x68
    };
    struct _M128A Xmm0;                                                     //0x70
    struct _M128A Xmm1;                                                     //0x80
    struct _M128A Xmm2;                                                     //0x90
    struct _M128A Xmm3;                                                     //0xa0
    struct _M128A Xmm4;                                                     //0xb0
    struct _M128A Xmm5;                                                     //0xc0
    union
    {
        ULONGLONG FaultAddress;                                             //0xd0
        ULONGLONG ContextRecord;                                            //0xd0
    };
    ULONGLONG Dr0;                                                          //0xd8
    ULONGLONG Dr1;                                                          //0xe0
    ULONGLONG Dr2;                                                          //0xe8
    ULONGLONG Dr3;                                                          //0xf0
    ULONGLONG Dr6;                                                          //0xf8
    ULONGLONG Dr7;                                                          //0x100
    ULONGLONG DebugControl;                                                 //0x108
    ULONGLONG LastBranchToRip;                                              //0x110
    ULONGLONG LastBranchFromRip;                                            //0x118
    ULONGLONG LastExceptionToRip;                                           //0x120
    ULONGLONG LastExceptionFromRip;                                         //0x128
    USHORT SegDs;                                                           //0x130
    USHORT SegEs;                                                           //0x132
    USHORT SegFs;                                                           //0x134
    USHORT SegGs;                                                           //0x136
    ULONGLONG TrapFrame;                                                    //0x138
    ULONGLONG Rbx;                                                          //0x140
    ULONGLONG Rdi;                                                          //0x148
    ULONGLONG Rsi;                                                          //0x150
    ULONGLONG Rbp;                                                          //0x158
    union
    {
        ULONGLONG ErrorCode;                                                //0x160
        ULONGLONG ExceptionFrame;                                           //0x160
    };
    ULONGLONG Rip;                                                          //0x168
    USHORT SegCs;                                                           //0x170
    UCHAR Fill0;                                                            //0x172
    UCHAR Logging;                                                          //0x173
    USHORT Fill1[2];                                                        //0x174
    ULONG EFlags;                                                           //0x178
    ULONG Fill2;                                                            //0x17c
    ULONGLONG Rsp;                                                          //0x180
    USHORT SegSs;                                                           //0x188
    USHORT Fill3;                                                           //0x18a
    ULONG Fill4;                                                            //0x18c
}; 
~~~
</code>
</pre> </details>


#### 编译器扩展 SEH

```c++
_try    // 挂入 SEH 链表
{
       
}
_except(/*过滤表达式*/) //异常过滤
{
  //异常处理程序
}  
```

对于过滤表达式的结果值，只能是-1、0、1，它们表示的含义如下：

EXCEPTION_EXECUTE_HANDLER (1) 执行except里面的代码
EXCEPTION_CONTINUE_SEARCH (0) 寻找下一个异常处理函数
EXCEPTION_CONTINUE_EXECUTION (-1) 返回出错位置重新执行