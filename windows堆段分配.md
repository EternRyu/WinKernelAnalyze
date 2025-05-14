## 架构

段堆由4个组件组成：</br>
>(1)后端管理器，为128~508KB大小的分配请求服务。它使用NT内存管理器提供的虚拟内存函数，创建并管理后端分配的块。</br>

>(2)可变尺寸(VS)分配组件为小于128KB的分配请求服务。它利用后端来创建VS
子段，VS块存放于此。</br>

>(3)LFH为<=16368字节的分配请求服务，但仅在分配尺寸被探测为通用用途时才可用。它利
用后端来创建LFH 子段，LFH块从这里分配。</br>

>(4)大块分配组件为>508KB的分配请求服务。它使用NT内存管理器提供的虚拟内存函数来进行分配和释放大块

![alt text](ImageFile\windows_segment_heap.png)

## 堆的创建
当段堆管理的堆被创建后，堆地址/句柄(此后一律称为`HeapBase`)会由
`HeapCreate()`或`RtlCreateHeap()`返回它指向一个`_SEGMENT_HEAP` 结构，与NT堆的`_HEAP` 结构十分相似
HeapBase 是中枢位置，各种段堆组件的状态都存储于此。
```c++
//0x580 bytes (sizeof)
struct _SEGMENT_HEAP
{
    struct RTL_HP_ENV_HANDLE EnvHandle;                                     //0x0
    ULONG Signature;                                                        //0x8
    ULONG GlobalFlags;                                                      //0xc
    ULONG Interceptor;                                                      //0x10
    USHORT ProcessHeapListIndex;                                            //0x14
    USHORT AllocatedFromMetadata:1;                                         //0x16
    union
    {
        struct _RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;                 //0x18
        struct
        {
            ULONG ReservedMustBeZero1;                                      //0x18
            VOID* UserContext;                                              //0x1c
            ULONG ReservedMustBeZero2;                                      //0x20
            VOID* Spare;                                                    //0x24
        };
    };
    ULONG LargeMetadataLock;                                                //0x40
    //用于追溯大块分配的状态
    struct _RTL_RB_TREE LargeAllocMetadata;       大块元数据的红黑树         //0x44
    volatile ULONG LargeReservedPages;     为所有的大块分配保留的页数         //0x4c
    volatile ULONG LargeCommittedPages;    为所有的大块分配提交的页数         //0x50
    union _RTL_RUN_ONCE StackTraceInitVar;                                  //0x54
    struct _HEAP_RUNTIME_MEMORY_STATS MemStats;                             //0x80
    USHORT GlobalLockCount;                                                 //0xac
    ULONG GlobalLockOwner;                                                  //0xb0
    ULONG ContextExtendLock;                                                //0xb4
    UCHAR* AllocatedBase;                                                   //0xb8
    UCHAR* UncommittedBase;                                                 //0xbc
    UCHAR* ReservedLimit;                                                   //0xc0
    struct _HEAP_SEG_CONTEXT SegContexts[2];                                //0x100
    //追溯可变尺寸分配和LFH状态的子结构字段
    struct _HEAP_VS_CONTEXT VsContext;   跟踪可变尺寸分配的状态              //0x200
    struct _HEAP_LFH_CONTEXT LfhContext;  跟踪LFH的状态                //0x2c0
}; 
```

```c++
//0x80 bytes (sizeof)
struct _HEAP_SEG_CONTEXT
{
    ULONG SegmentMask;                                                      //0x0
    UCHAR UnitShift;                                                        //0x4
    UCHAR PagesPerUnitShift;                                                //0x5
    UCHAR FirstDescriptorIndex;                                             //0x6
    UCHAR CachedCommitSoftShift;                                            //0x7
    UCHAR CachedCommitHighShift;                                            //0x8
    union
    {
        UCHAR LargePagePolicy:3;                                            //0x9
        UCHAR FullDecommit:1;                                               //0x9
        UCHAR ReleaseEmptySegments:1;                                       //0x9
        UCHAR AllFlags;                                                     //0x9
    } Flags;                                                                //0x9
    ULONG MaxAllocationSize;                                                //0xc
    SHORT OlpStatsOffset;                                                   //0x10
    SHORT MemStatsOffset;                                                   //0x12
    VOID* LfhContext;                                                       //0x14
    VOID* VsContext;                                                        //0x18
    struct RTL_HP_ENV_HANDLE EnvHandle;                                     //0x1c
    VOID* Heap;                                                             //0x24
    ULONG SegmentLock;                                                      //0x40
    //追溯后端分配状态的字段
    struct _LIST_ENTRY SegmentListHead; 堆所控制的段链表头                   //0x44
    ULONG SegmentCount;   对所控制的段数量                                   //0x4c
    struct _RTL_RB_TREE FreePageRanges;   空闲后端块的红黑树                 //0x50
    ULONG FreeSegmentListLock;                                              //0x58
    struct _SINGLE_LIST_ENTRY FreeSegmentList[2];                           //0x5c
}; 
```
堆由
`RtlpHpSegHeapCreate()` 分配并初始化。
`NtAllocateVirtualMemory()` 用于保留和提交堆的虚拟内存</br>
尺寸的变化取决于处理器的数量，提交的尺寸就是`_SEGMENT_HEAP` 结构的大小

在`_SEGMENT_HEAP` 结构下面剩余的保留内存称为LFH上下文扩展，它被动态的提交以为激活的LFH 桶存储必要的数据。