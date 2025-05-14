# Wow64
如ExitProcess调用流程
```c++
ExitProcess
->NtTerminateProcess
->Wow64SystemServiceCall
->Wow64Transition
->KiFastSystemCall
```

从ntdll中的一个NtResumeThread调用开始出发。这个函数将调用Wow64SystemServiceCall函数，而后者会执行Wow64Transition函数。最后，由KiFastSystemCall函数完成从32位运行模式到64位运行模式的过渡

wow64cpu!RunSimulatedCode中的重要部分 _TEB64->WOW32Reserved

![alt text](ImageFile\RunSimulatedCode.png)

检索到的TLS数据是一个未公开的数据结构`WOW64_CPURESERVED`它包含了WOW64层用来设置和恢复32位和64位边界的寄存器数据和CPU状态信息。在这个结构体中，还有一个WOW64_CONTEXT结构体，微软网站上提供了部分文档

往后的函数使用了调用门

![alt text](ImageFile\Wow64_call.png)

查表进入64位模式
![alt text](ImageFile\Wow64_call_2.png)


# 利用Wow64在32位运行64位程序

```c++
//32位程序切换到64位程序
//通过retf修改EIP和CS寄存器 去到64位的段
#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }


//64位程序切换回32位程序
//通过retf修改EIP和CS寄存器 返回32位的段
#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }
```