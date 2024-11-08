# 页表基址(PTE)
x64系统中，页表基址不再是固定的值，而是每次系统启动后随机生成的<br>
`windows 10 14316开始实现了页表随机化`<br>
可以在WinDbg中查看0地址对应的线性地址来确定当前的页表基址<br>
```
0: kd> !pte 0
                                           VA 0000000000000000
PXE at FFFF80C060301000    PPE at FFFF80C060200000    PDE at FFFF80C040000000    PTE at FFFF808000000000
contains 8A00000004150867  contains 0000000000000000
pfn 4150      ---DA--UW-V  contains 0000000000000000
not valid
```

### 如何找到PTE基址
以当前cr3为物理地址映射成虚拟地址，相当于访问cr3所指向的pml4t表<br>
然后在这个[512]的表（数组）中找到一项指向当前cr3的,也就是所谓的页表自映射<br>
`四级页表分别称为PML4E、PDPTE、PDE、PTE`<br>
这一项PML4E所指向的物理页page_frame_number代表它自己这个表<br>
满足这样的映射关系的PML4E所代表的虚拟地址空间也就相当于页表本身<br>
只要找到指向当前cr3的pml4e index<br>
将其左移39位并补上FFFF000000000000就得到了PTE_BASE<br>

```
win10 1803之后MmMapIoSpace不再允许映射页表相关的物理地址，因此只能用MmGetVirtualForPhysical代替，或者自己实现映射物理地址
```

实现：
```
	PHYSICAL_ADDRESS physical_address;
	
	physical_address.QuadPart = __readcr3() & 0xfffffffffffff000;   // 获取CR3寄存器，清除低12位
	PULONG64 pxe_ptr = MmGetVirtualForPhysical(physical_address);   // 获取其所在的虚拟地址
	ULONG64 index = 0;
	// 遍历比较找到页表自映射
	while ((pxe_ptr[index] & 0xfffffffff000) != physical_address.QuadPart)
	{
		index++;
		if (index >= 512)
		{
			return FALSE;
		}
	}
	// 计算pte基址
	lpPageTableBase->PTE_Base= ((index + 0x1fffe00) << 39);
	lpPageTableBase->PDE_Base = lpPageTableBase->PTE_Base + (index << 30);
	lpPageTableBase->PPE_Base = lpPageTableBase->PTE_Base + (index << 30) + (index << 21);
	lpPageTableBase->PXE_Base = (void*)(lpPageTableBase->PPE_Base + (index << 12));
```

MmGetVirtualForPhysical函数实现可以从内核中找到，如下：<br>

```
ULONG64 MmGetVirtualForPhysical(unsigned __int64 a1)
{
    return (a1 & 0xFFF) + (*(ULONG64 *)(48 * (a1 >> 12) - 0x57FFFFFFFF8i64) << 25 >> 16);
}
```