(Structured Exception Handler Overwrite Protection)
## 结构化异常处理覆盖保护
SEHOP的核心是检测程序栈中的所有SEH结构链表，特别是最后一个SEH结构，它拥有一个特殊的异常处理函数指针，指向的是一个位于NTDLL中的函数

SEHOP保护机制就是：顺着SEH异常处理指针一直找下去，如果说最终的那个SEH处理函数是系统预定的终极异常处理函数，那说明SEH异常处理链完整，验证通过，如果不是，则会验证失败，直接退出。


相关实现RtlDispatchException


```
•SEH结构都必须在栈上；

•最后一个SEH结构也必须在栈上；

•所有的SEH结构都必须是4字节对齐的；

•SEH结构中的handle（处理函数地址）必须不在栈上；

•最后一个SEH结构的handle必须是ntdll!FinalExceptionHandler函数；

•最后一个SEH结构的next seh指针必须为特定值0xFFFFFFFF；
```

### 绕过方式
```
1.覆盖返回地址
2.攻击虚函数
3.构造SEH异常处理链
```