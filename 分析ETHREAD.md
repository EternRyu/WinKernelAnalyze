# ETHREAD 
ETHREAD(执行体线程块)是执行体层上的线程对象的数据结构。在windows内核中，每个进程的每一个线程都对应着一个ETHREAD数据结构

```
//0x898 bytes (sizeof)
struct _ETHREAD
{
    struct _KTHREAD Tcb;    //内嵌KTHREAD对象                         //0x0
    union _LARGE_INTEGER CreateTime;  //线程的创建时间，它是在线程创建时被赋值的       //0x430
    union
    {
        union _LARGE_INTEGER ExitTime;  //包含了线程的退出时间。它是在线程退出函数中被赋值的        //0x438
        struct _LIST_ENTRY KeyedWaitChain;  //用于带键事件的等待链表   //0x438
    };
    union
    {
        struct _LIST_ENTRY PostBlockList;//被用于一个线程向"配置管理器"登记注册表键的变化通知 //0x448
        struct
        {
            VOID* ForwardLinkShadow;                                        //0x448
            VOID* StartAddress;//包含了线程的启动地址，这是真正的线程启动地址，即入口地址。也就是我们在创建线程的之后指定的入口函数的地址 //0x450
        };
    };
    union
    {
        struct _TERMINATION_PORT* TerminationPort; //当一个线程退出时，系统会通知所有已经登记过要接收其终止事件的那些"端口" //0x458
        struct _ETHREAD* ReaperLink;  //仅在线程退出时使用。当线程被终止时，该节点将被挂到PsReaperListHead链表上(用以告知内核当前线程将要退出了，请收到相关的线程资源)，所以，在线程回收器(reaper)的工作项目(WorkItem)中该线程的内核栈得以收回                                      //0x458
        VOID* KeyedWaitValue;                                               //0x458
    };
    ULONGLONG ActiveTimerListLock;     //链表中包含了当前线程的所有定时器         //0x460
    struct _LIST_ENTRY ActiveTimerListHead;  //这个链表(包含当前线程的所有定时器的双链表)的自旋锁。使用自旋锁可以把原本可能发生的并行事件导致的问题通过强制串行化得到解决。比如对线程中的定时器这个互斥
资源就典型的需要串行化，否则将导致定时器的错乱等很多问题 //0x468
    struct _CLIENT_ID Cid;   //包含了线程的"唯一标识符"           //0x478
    union
    {
        struct _KSEMAPHORE KeyedWaitSemaphore;  //LPC处理带键的事      //0x488
        struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x488
    };
    union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                       //0x4a8
    struct _LIST_ENTRY IrpList; //包含了当前线程所有正在处理但尚未完成的I/O请求(Irp对象)  //0x4b0
    ULONGLONG TopLevelIrp; //指向线程的顶级IRP       //0x4c0
    struct _DEVICE_OBJECT* DeviceToVerify; //指向的是一个"待检验"的设备，当磁盘或CD-ROM设备的驱动程序"发现"自从上一次该线程访问该设备以来，该设备有了"变化"，就会设置线程的DeviceToVerify域，从而使最高层的驱动程序(比如文件系统)，可以检测到设备变化   //0x4c8
    VOID* Win32StartAddress; //包含的是windows子系统接收到的线程启动地址，即CreateThread API函数接收到的线程启动地址 windows子系统接收到的线程启动地址，即CreateThread中指定的那个函数入口地址       //0x4d0
    VOID* ChargeOnlySession;                                                //0x4d8
    VOID* LegacyPowerObject;                                                //0x4e0
    struct _LIST_ENTRY ThreadListEntry;  //每个线程都会加入到它所属的EPROCESS结构的ThreadListHead双链表中   //0x4e8
    struct _EX_RUNDOWN_REF RundownProtect;  //是线程的停止保护锁，对于跨线程引用TEB结构或者挂起线程的执行等操作，需要获得此锁才能运行，以避免在操作过程中线程被销毁     //0x4f8
    struct _EX_PUSH_LOCK ThreadLock;  //一把推锁，用户保护线程的数据属性，例如PspLockThreadSecurityExclusive和PspLockThreadSecurityShared利用该域来保护线程的安全属性      //0x500
    ULONG ReadClusterSize; //指明了在一次I/O操作中读取多少个页面，用于页面交换文件和内存映射文件的读操作 //0x508
    volatile LONG MmLockOrdering;                                           //0x50c
    union
    {
        ULONG CrossThreadFlags;   //  针对跨线程访问的标志位      //0x510
        struct
        {
            ULONG Terminated:1;    //线程已终止操作                  //0x510
            ULONG ThreadInserted:1;                                         //0x510
            ULONG HideFromDebugger:1; //该线程对于调试器不可见          //0x510
            ULONG ActiveImpersonationInfo:1; //线程正在模仿          //0x510
            ULONG HardErrorsAreDisabled:1;    //对于该线程，硬件错误无效  //0x510
            ULONG BreakOnTermination:1; //调试器在线程终止时停下该线程        //0x510
            ULONG SkipCreationMsg:1; //不向调试器发送创建消息        //0x510
            ULONG SkipTerminationMsg:1; //不向调试器发送终止消息    //0x510
            ULONG CopyTokenOnOpen:1;                                        //0x510
            ULONG ThreadIoPriority:3;                                       //0x510
            ULONG ThreadPagePriority:3;                                     //0x510
            ULONG RundownFail:1;                                            //0x510
            ULONG UmsForceQueueTermination:1;                               //0x510
            ULONG IndirectCpuSets:1;                                        //0x510
            ULONG DisableDynamicCodeOptOut:1;                               //0x510
            ULONG ExplicitCaseSensitivity:1;                                //0x510
            ULONG PicoNotifyExit:1;                                         //0x510
            ULONG DbgWerUserReportActive:1;                                 //0x510
            ULONG ForcedSelfTrimActive:1;                                   //0x510
            ULONG SamplingCoverage:1;                                       //0x510
            ULONG ReservedCrossThreadFlags:8;                               //0x510
        };
    };
    union
    {
        ULONG SameThreadPassiveFlags; //只有在最低中断级别(被动级别)上才可以访问的标志，并且只能被该线程自身访问，所以对这些标志位的访问不需要互锁操作                                      //0x514
        struct
        {
            ULONG ActiveExWorker:1;                                         //0x514
            ULONG MemoryMaker:1;                                            //0x514
            ULONG StoreLockThread:2;                                        //0x514
            ULONG ClonedThread:1;                                           //0x514
            ULONG KeyedEventInUse:1;                                        //0x514
            ULONG SelfTerminate:1;                                          //0x514
            ULONG RespectIoPriority:1;                                      //0x514
            ULONG ActivePageLists:1;                                        //0x514
            ULONG SecureContext:1;                                          //0x514
            ULONG ZeroPageThread:1;                                         //0x514
            ULONG WorkloadClass:1;                                          //0x514
            ULONG ReservedSameThreadPassiveFlags:20;                        //0x514
        };
    };
    union
    {
        ULONG SameThreadApcFlags; //是一些在APC中断级别(也是很低的级别)上被该线程自身访问的标志位，同样地，对这些标志位的访问也不需要互锁操作  //0x518
        struct
        {
            UCHAR OwnsProcessAddressSpaceExclusive:1;                       //0x518
            UCHAR OwnsProcessAddressSpaceShared:1;                          //0x518
            UCHAR HardFaultBehavior:1;                                      //0x518
            volatile UCHAR StartAddressInvalid:1;                           //0x518
            UCHAR EtwCalloutActive:1;                                       //0x518
            UCHAR SuppressSymbolLoad:1;                                     //0x518
            UCHAR Prefetching:1;                                            //0x518
            UCHAR OwnsVadExclusive:1;                                       //0x518
            UCHAR SystemPagePriorityActive:1;                               //0x519
            UCHAR SystemPagePriority:3;                                     //0x519
            UCHAR AllowUserWritesToExecutableMemory:1;                      //0x519
            UCHAR AllowKernelWritesToExecutableMemory:1;                    //0x519
            UCHAR OwnsVadShared:1;                                          //0x519
        };
    };
    UCHAR CacheManagerActive;                                               //0x51c
    UCHAR DisablePageFaultClustering;  //用于控制页面交换的聚集与否         //0x51d
    UCHAR ActiveFaultCount;   //包含了正在进行之中的页面错误数量       //0x51e
    UCHAR LockOrderState;                                                   //0x51f
    ULONG PerformanceCountLowReserved;                                      //0x520
    LONG PerformanceCountHighReserved;                                      //0x524
    ULONGLONG AlpcMessageId;                                                //0x528
    union
    {
        VOID* AlpcMessage;                                                  //0x530
        ULONG AlpcReceiveAttributeSet;                                      //0x530
    };
    struct _LIST_ENTRY AlpcWaitListEntry;                                   //0x538
    LONG ExitStatus;     //线程的退出状态                    //0x548
    ULONG CacheManagerCount;                                                //0x54c
    ULONG IoBoostCount;                                                     //0x550
    ULONG IoQoSBoostCount;                                                  //0x554
    ULONG IoQoSThrottleCount;                                               //0x558
    ULONG KernelStackReference;                                             //0x55c
    struct _LIST_ENTRY BoostList;                                           //0x560
    struct _LIST_ENTRY DeboostList;                                         //0x570
    ULONGLONG BoostListLock;                                                //0x580
    ULONGLONG IrpListLock;                                                  //0x588
    VOID* ReservedForSynchTracking;                                         //0x590
    struct _SINGLE_LIST_ENTRY CmCallbackListHead;                           //0x598
    struct _GUID* ActivityId;                                               //0x5a0
    struct _SINGLE_LIST_ENTRY SeLearningModeListHead;                       //0x5a8
    VOID* VerifierContext;                                                  //0x5b0
    VOID* AdjustedClientToken;                                              //0x5b8
    VOID* WorkOnBehalfThread;                                               //0x5c0
    struct _PS_PROPERTY_SET PropertySet;                                    //0x5c8
    VOID* PicoContext;                                                      //0x5e0
    ULONGLONG UserFsBase;                                                   //0x5e8
    ULONGLONG UserGsBase;                                                   //0x5f0
    struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x5f8
    union
    {
        ULONGLONG SelectedCpuSets;                                          //0x600
        ULONGLONG* SelectedCpuSetsIndirect;                                 //0x600
    };
    struct _EJOB* Silo;                                                     //0x608
    struct _UNICODE_STRING* ThreadName;                                     //0x610
    struct _CONTEXT* SetContextState;                                       //0x618
    ULONG LastExpectedRunTime;                                              //0x620
    ULONG HeapData;                                                         //0x624
    struct _LIST_ENTRY OwnerEntryListHead;                                  //0x628
    ULONGLONG DisownedOwnerEntryListLock;                                   //0x638
    struct _LIST_ENTRY DisownedOwnerEntryListHead;                          //0x640
    struct _KLOCK_ENTRY LockEntries[6];                                     //0x650
    VOID* CmDbgInfo;                                                        //0x890
}; 
```