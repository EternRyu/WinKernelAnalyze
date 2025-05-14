# X64 SMAP SMEP 位
64位下CR4寄存器新添加的两个标志位SMAP和SMEP
![alt text](ImageFile\CR4.png)


# Supervisor Mode Execution Prevention (SMEP)

位于Cr4的第20位，作用是让处于内核权限的CPU无法执行用户代码


# Supervisor Mode Access Prevention (SMAP)

位于Cr4的第21位，作用是让处于内核权限的CPU无法读写用户代码

# 绕过
通过ROP返回导向编程找到合适的代码位置执行将Cr4的SMEP/SMAP置零

触发思路
构造IDT后门
将 IDT 0x21号中断的函数地址改为IntEntry的地址
当中断执行来到IntEntry时通过iretq返回

```c++
IntEntry    Proc
    iretq
IntEntry    Endp

CallInt Proc
    int 21h
    ret
CallInt Endp
```