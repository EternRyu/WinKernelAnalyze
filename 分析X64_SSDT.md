## SSDT 系统服务描述符表 [System Services Descriptor Table]

>Win7 32 位系统中，SSDT 在内核 Ntoskrnl.exe 中导出，直接获取导出符号 KeServiceDescriptorTable。
>
>而在 64 位系统中，SSDT 表并没有在内核 Ntoskrnl.exe 中导出<br>
>Win7 x64 与 Win10 64（Win10低版本）中,通过 __readmsr(0xC0000082) 获取内核函数 KiSystemCall64 的地址<br>
>KiSystemCall64 中调用了 KeServiceDescriptorTable 和 KeServiceDescriptorTableShadow<br>
>win10 高版本中 __readmsr(0xC0000082) 返回 KiSystemCall64Shadow 函数
>>在高版本当中msr在开启内核隔离模式下获取到的是KiSystemCall64Shadow函数地址<br>在未开启内核隔离模式下获取到的是KiSystemCall64函数地址
>