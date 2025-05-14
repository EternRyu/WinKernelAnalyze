# DEP 数据执行保护

DEP的主要作用是阻止数据页（默认的堆，栈以及内存池页）执行代码。分为软件DEP和硬件DEP，其中软件DEP就是SafeSEH。而硬件DEP操作系统会通过设置内存页的NX/XD属性标记是否运行在本页执行指令

软件DEP(Software DEP)
硬件DEP(Hardware-enforced DEP)

通过调用接口关闭DEP(NtSetInformationProcess)
```
DEP分为4种工作态

Optin：默认仅保护Windows系统组件
Optout：为排除列表程序外的所有程序和服务启用DEP
AlwaysOn：对所有进程启用DEP保护
AlwaysOff：对所有进程都禁用DEP
```