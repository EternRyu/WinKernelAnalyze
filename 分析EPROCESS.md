# EPROCESS
EPEOCESS(执行体进程块，E是Execute的意思，注意和KPROCESS区分开来)位于内核层之上 
```
//0xa40 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS Pcb;                         //内核层进程结构体           //0x0
    struct _EX_PUSH_LOCK ProcessLock;   //自旋锁 用于保护EPROCESS数据成员的同步 //0x438
    VOID* UniqueProcessId;          //进程的唯一PID                            //0x440
    struct _LIST_ENTRY ActiveProcessLinks; //双向链表 当前系统活动的所有进程 全局表头 PsActiveProcessHead //0x448
    struct _EX_RUNDOWN_REF RundownProtect;//进程的停止保护锁 当进程最后被销毁时 要等到其他进程和线程释放了此锁才可以继续 //0x458
    union
    {
        ULONG Flags2;                                                       //0x460
        struct
        {
            ULONG JobNotReallyActive:1;                                     //0x460
            ULONG AccountingFolded:1;                                       //0x460
            ULONG NewProcessReported:1;                                     //0x460
            ULONG ExitProcessReported:1;                                    //0x460
            ULONG ReportCommitChanges:1;                                    //0x460
            ULONG LastReportMemory:1;                                       //0x460
            ULONG ForceWakeCharge:1;                                        //0x460
            ULONG CrossSessionCreate:1;                                     //0x460
            ULONG NeedsHandleRundown:1;                                     //0x460
            ULONG RefTraceEnabled:1;                                        //0x460
            ULONG PicoCreated:1;                                            //0x460
            ULONG EmptyJobEvaluated:1;                                      //0x460
            ULONG DefaultPagePriority:3;                                    //0x460
            ULONG PrimaryTokenFrozen:1;                                     //0x460
            ULONG ProcessVerifierTarget:1;                                  //0x460
            ULONG RestrictSetThreadContext:1;                               //0x460
            ULONG AffinityPermanent:1;                                      //0x460
            ULONG AffinityUpdateEnable:1;                                   //0x460
            ULONG PropagateNode:1;                                          //0x460
            ULONG ExplicitAffinity:1;                                       //0x460
            ULONG ProcessExecutionState:2;                                  //0x460
            ULONG EnableReadVmLogging:1;                                    //0x460
            ULONG EnableWriteVmLogging:1;                                   //0x460
            ULONG FatalAccessTerminationRequested:1;                        //0x460
            ULONG DisableSystemAllowedCpuSet:1;                             //0x460
            ULONG ProcessStateChangeRequest:2;                              //0x460
            ULONG ProcessStateChangeInProgress:1;                           //0x460
            ULONG InPrivate:1;                                              //0x460
        };
    };
    union
    {
        ULONG Flags;  //域包含了进程的标志位，这些标志位反映了进程的当前状态和配置   //0x464
        struct
        {
            ULONG CreateReported:1;                                         //0x464
            ULONG NoDebugInherit:1;                                         //0x464
            ULONG ProcessExiting:1;                                         //0x464
            ULONG ProcessDelete:1;                                          //0x464
            ULONG ManageExecutableMemoryWrites:1;                           //0x464
            ULONG VmDeleted:1;                                              //0x464
            ULONG OutswapEnabled:1;                                         //0x464
            ULONG Outswapped:1;                                             //0x464
            ULONG FailFastOnCommitFail:1;                                   //0x464
            ULONG Wow64VaSpace4Gb:1;                                        //0x464
            ULONG AddressSpaceInitialized:2;                                //0x464
            ULONG SetTimerResolution:1;                                     //0x464
            ULONG BreakOnTermination:1;                                     //0x464
            ULONG DeprioritizeViews:1;                                      //0x464
            ULONG WriteWatch:1;                                             //0x464
            ULONG ProcessInSession:1;                                       //0x464
            ULONG OverrideAddressSpace:1;                                   //0x464
            ULONG HasAddressSpace:1;                                        //0x464
            ULONG LaunchPrefetched:1;                                       //0x464
            ULONG Background:1;                                             //0x464
            ULONG VmTopDown:1;                                              //0x464
            ULONG ImageNotifyDone:1;                                        //0x464
            ULONG PdeUpdateNeeded:1;                                        //0x464
            ULONG VdmAllowed:1;                                             //0x464
            ULONG ProcessRundown:1;                                         //0x464
            ULONG ProcessInserted:1;                                        //0x464
            ULONG DefaultIoPriority:3;                                      //0x464
            ULONG ProcessSelfDelete:1;                                      //0x464
            ULONG SetTimerResolutionLink:1;                                 //0x464
        };
    };
    union _LARGE_INTEGER CreateTime;      //创建时间                         //0x468
    ULONGLONG ProcessQuotaUsage[2];        //进程的内存使用量                //0x470
    ULONGLONG ProcessQuotaPeak[2];         //进程的内存尖峰使用量             //0x480
    ULONGLONG PeakVirtualSize;         //虚拟内存大小的尖峰值                 //0x490
    ULONGLONG VirtualSize;              //进程的虚拟内存大小                //0x498
    struct _LIST_ENTRY SessionProcessLinks;     //会话的进程链表           //0x4a0
    union
    {
        VOID* ExceptionPortData;       //异常端口数据                         //0x4b0
        ULONGLONG ExceptionPortValue;  //异常端口值                           //0x4b0
        ULONGLONG ExceptionPortState:3;//异常端口状态                         //0x4b0
    };
    struct _EX_FAST_REF Token;        //令牌                                 //0x4b8
    ULONGLONG MmReserved;                                                   //0x4c0
    struct _EX_PUSH_LOCK AddressCreationLock;守护互斥体锁，用于保护对地址空间的操作//0x4c8
    struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x4d0
    struct _ETHREAD* RotateInProgress;                                      //0x4d8
    struct _ETHREAD* ForkInProgress;指向正在复制地址空间的那个线程，仅当在地址空间复制过程中，此域才会被赋值，在其他情况下为NULL。 //0x4e0
    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
    struct _RTL_AVL_TREE CloneRoot; //指向一个平衡树的根，当进程地址空间复制时，此树被创建，创建出来后，一直到进程退出的时候才被销毁 //0x4f0
    volatile ULONGLONG NumberOfPrivatePages;   //进程私有页面的数量   //0x4f8
    volatile ULONGLONG NumberOfLockedPages;     // 进程被锁住的页面的数量   //0x500
    VOID* Win32Process;                                                     //0x508
    struct _EJOB* volatile Job; //当一个进程属于一个job(作业)的时候，它才会指向一个_EJOB对象 //0x510
    VOID* SectionObject;  // 代表进程的内存区对象(进程的可执行映像文件的内存区对象)      //0x518
    VOID* SectionBaseAddress;  //内存区对象的基地址                   //0x520
    ULONG Cookie; //存放的是一个代表该进程的随机值，当第一次通过NtQueryInformationProcess函数获取此Cookie值的时候，系统会生成一个随机值，以后就用此值代表此进程 //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;  //用于监视一个进程的页面错误，一旦启用了页面错误监视功能(由全局变量PsWatchEnabled开关来控制)，则每次发生页面错误都会将该页面错误记录到WorkingSetWatch域的WatchInfo成员数组中，知道数组满为止                           //0x530
    VOID* Win32WindowStation; //进程所属的窗口站的句柄。由于句柄的值是由每个进程的句柄表来决定的，所以，两个进程即使同属于一个窗口站，它们的Win32WindowStation也可能不同，但指向的窗口站对象是相同的。窗口站是由windows子系统来管理和控制的            //0x538
    VOID* InheritedFromUniqueProcessId;   //父进程的标识符                    //0x540
    volatile ULONGLONG OwnerProcessId;                                      //0x548
    struct _PEB* Peb;                //指向进程环境块PEB的指针      //0x550
    struct _MM_SESSION_SPACE* Session;      //进程所在的系统会话               //0x558
    VOID* Spare1;                                                           //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;  //指向进程的配额块         //0x568
    struct _HANDLE_TABLE* ObjectTable;       //当前进程的句柄表              //0x570
    VOID* DebugPort;                         //调试端口                     //0x578
    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
    VOID* DeviceMap;//指向进程使用的设备表，通常情况下同一个会话中的进程共享同样的设备表   //0x588
    VOID* EtwDataSource;                                                    //0x590
    ULONGLONG PageDirectoryPte;                                             //0x598
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    UCHAR ImageFileName[15];              //进程名称   过长会截断            //0x5a8
    UCHAR PriorityClass;      //进程的优先级程度         //0x5b7
    VOID* SecurityPort;          //安全端口，指向该进程域lsass.exe进程之间的跨进程通信端口       //0x5b8
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;   //包含了创建进程时指定的进程映像全路径名，我们之前学过的ImageFileName域实际上就是从这里"提取"出来的。   //0x5c0
    struct _LIST_ENTRY JobLinks;  //job链表 链表头为全局变量PspJobList  //0x5c8
    VOID* HighestUserAddress;                                               //0x5d8
    struct _LIST_ENTRY ThreadListHead;  //该链表中包含了一个进程中的所有"线程"。即EPROCESS中的ThreadListHead域的链表中包含了各个子线程的ETHREAD结构中的ThreadListHead节点。                                    //0x5e0
    volatile ULONG ActiveThreads;    //记录了当前进程有多少活动线程。当该值减为0时，所有的线程将退出，于是进程也退出  //0x5f0
    ULONG ImagePathHash;                                                    //0x5f4
    ULONG DefaultHardErrorProcessing;  //指定了默认的硬件错误处理，默认为1        //0x5f8
    LONG LastThreadExitStatus;  //记录了刚才最后一个线程的退出状态。当主线程的入口点函数(WinMain, wWinMain, main, wmain)返回时，会返回到C/C++"运行库启动代码"，后者将正确清理进程使用的全部C运行时资源       //0x5fc
    struct _EX_FAST_REF PrefetchTrace; //快速引用，指向与该进程关联的一个"预取痕迹结构"，以支持该进程的预取           //0x600
    VOID* LockedPagesList;   //一个指向LOCK_HEADER结构的指针  包含了一个链表头，windows通过此链表来记录哪些页面已被锁住(这里所谓的锁住和Mdll中的映射机制有关，本质上就是把用户空间下的内存地址锁定到内核空间中以便访问)    //0x608
    union _LARGE_INTEGER ReadOperationCount; //记录了当前进程NtReadFile服务被调用的次数   //0x610
    union _LARGE_INTEGER WriteOperationCount;  //记录了当前进程NtWriteFile系统服务被调用的次数//0x618
    union _LARGE_INTEGER OtherOperationCount; //记录了除读写操作以外的其他IO服务的次数 //0x620
    union _LARGE_INTEGER ReadTransferCount;//记录了IO 读 操作"完成"的次数 //0x628
    union _LARGE_INTEGER WriteTransferCount;//记录了IO 写 操作"完成"的次数 //0x630
    union _LARGE_INTEGER OtherTransferCount; //记录了除读写操作以外操作完成的次数 //0x638
    ULONGLONG CommitChargeLimit;                                            //0x640
    volatile ULONGLONG CommitCharge; //存储了一个进程的虚拟内存已提交的"页面数量" //0x648
    volatile ULONGLONG CommitChargePeak;                                    //0x650
    struct _MMSUPPORT_FULL Vm; //windows为每个进程管理虚拟内存的重要数据结构成员  //0x680
    struct _LIST_ENTRY MmProcessLinks; //所有拥有自己地址空间的进程都将加入到一个双链表中，链表头是全局变量MmProcessList。当进程地址空间被初始创建时，MmProcessLinks节点会被加入到此全局链表中。当进程地址空间被销毁时，该节点脱离此链表。此全局链表的存在使得windows系统共可以方便地执行一些全局的内存管理任务，同时也可以被我们用来进行进程枚举                                     //0x7c0
    ULONG ModifiedPageCount; //记录了该进程中已修改的页面的数量，即"脏页面数量"，这和缓存的读写有关                                               //0x7d0
    LONG ExitStatus;  //进程的退出状态码                          //0x7d4
    struct _RTL_AVL_TREE VadRoot; //指向一个平衡二叉树的根，用于管理该进程的虚拟地址空间    //0x7d8
    VOID* VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x800
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
    ULONG RequestedTimerResolution;                                         //0x838
    ULONG SmallestTimerResolution;                                          //0x83c
    union _LARGE_INTEGER ExitTime;    //退出时间                             //0x840
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x848
    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x850
    ULONG ActiveThreadsHighWatermark;                                       //0x858
    ULONG LargePrivateVadCount;                                             //0x85c
    struct _EX_PUSH_LOCK ThreadListLock;                                    //0x860
    VOID* WnfContext;                                                       //0x868
    struct _EJOB* ServerSilo;                                               //0x870
    UCHAR SignatureLevel;                                                   //0x878
    UCHAR SectionSignatureLevel;                                            //0x879
    struct _PS_PROTECTION Protection;                                       //0x87a
    UCHAR HangCount:3;                                                      //0x87b
    UCHAR GhostCount:3;                                                     //0x87b
    UCHAR PrefilterException:1;                                             //0x87b
    union
    {
        ULONG Flags3;                                                       //0x87c
        struct
        {
            ULONG Minimal:1;                                                //0x87c
            ULONG ReplacingPageRoot:1;                                      //0x87c
            ULONG Crashed:1;                                                //0x87c
            ULONG JobVadsAreTracked:1;                                      //0x87c
            ULONG VadTrackingDisabled:1;                                    //0x87c
            ULONG AuxiliaryProcess:1;                                       //0x87c
            ULONG SubsystemProcess:1;                                       //0x87c
            ULONG IndirectCpuSets:1;                                        //0x87c
            ULONG RelinquishedCommit:1;                                     //0x87c
            ULONG HighGraphicsPriority:1;                                   //0x87c
            ULONG CommitFailLogged:1;                                       //0x87c
            ULONG ReserveFailLogged:1;                                      //0x87c
            ULONG SystemProcess:1;                                          //0x87c
            ULONG HideImageBaseAddresses:1;                                 //0x87c
            ULONG AddressPolicyFrozen:1;                                    //0x87c
            ULONG ProcessFirstResume:1;                                     //0x87c
            ULONG ForegroundExternal:1;                                     //0x87c
            ULONG ForegroundSystem:1;                                       //0x87c
            ULONG HighMemoryPriority:1;                                     //0x87c
            ULONG EnableProcessSuspendResumeLogging:1;                      //0x87c
            ULONG EnableThreadSuspendResumeLogging:1;                       //0x87c
            ULONG SecurityDomainChanged:1;                                  //0x87c
            ULONG SecurityFreezeComplete:1;                                 //0x87c
            ULONG VmProcessorHost:1;                                        //0x87c
            ULONG VmProcessorHostTransition:1;                              //0x87c
            ULONG AltSyscall:1;                                             //0x87c
            ULONG TimerResolutionIgnore:1;                                  //0x87c
            ULONG DisallowUserTerminate:1;                                  //0x87c
        };
    };
    LONG DeviceAsid;                                                        //0x880
    VOID* SvmData;                                                          //0x888
    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x890
    ULONGLONG SvmLock;                                                      //0x898
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
    VOID* PicoContext;                                                      //0x8c0
    VOID* EnclaveTable;                                                     //0x8c8
    ULONGLONG EnclaveNumber;                                                //0x8d0
    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x8d8
    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
    VOID* VmContext;                                                        //0x8f0
    ULONGLONG SequenceNumber;                                               //0x8f8
    ULONGLONG CreateInterruptTime;                                          //0x900
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
    ULONGLONG LastAppStateUpdateTime;                                       //0x918
    ULONGLONG LastAppStateUptime:61;                                        //0x920
    ULONGLONG LastAppState:3;                                               //0x920
    volatile ULONGLONG SharedCommitCharge;                                  //0x928
    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x930
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x938
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x948
            ULONGLONG DefaultCpuSets;                                       //0x950
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
        };
    };
    VOID* DiskIoAttribution;                                                //0x958
    VOID* DxgProcess;                                                       //0x960
    ULONG Win32KFilterSet;                                                  //0x968
    unionvolatile _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x970
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
        struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x9a0
    };
    union
    {
        ULONG MitigationFlags;                                              //0x9d0
        struct
        {
            ULONG ControlFlowGuardEnabled:1;                                //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled:1;               //0x9d0
            ULONG ControlFlowGuardStrict:1;                                 //0x9d0
            ULONG DisallowStrippedImages:1;                                 //0x9d0
            ULONG ForceRelocateImages:1;                                    //0x9d0
            ULONG HighEntropyASLREnabled:1;                                 //0x9d0
            ULONG StackRandomizationDisabled:1;                             //0x9d0
            ULONG ExtensionPointDisable:1;                                  //0x9d0
            ULONG DisableDynamicCode:1;                                     //0x9d0
            ULONG DisableDynamicCodeAllowOptOut:1;                          //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade:1;                 //0x9d0
            ULONG AuditDisableDynamicCode:1;                                //0x9d0
            ULONG DisallowWin32kSystemCalls:1;                              //0x9d0
            ULONG AuditDisallowWin32kSystemCalls:1;                         //0x9d0
            ULONG EnableFilteredWin32kAPIs:1;                               //0x9d0
            ULONG AuditFilteredWin32kAPIs:1;                                //0x9d0
            ULONG DisableNonSystemFonts:1;                                  //0x9d0
            ULONG AuditNonSystemFontLoading:1;                              //0x9d0
            ULONG PreferSystem32Images:1;                                   //0x9d0
            ULONG ProhibitRemoteImageMap:1;                                 //0x9d0
            ULONG AuditProhibitRemoteImageMap:1;                            //0x9d0
            ULONG ProhibitLowILImageMap:1;                                  //0x9d0
            ULONG AuditProhibitLowILImageMap:1;                             //0x9d0
            ULONG SignatureMitigationOptIn:1;                               //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries:1;                         //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore:1;               //0x9d0
            ULONG LoaderIntegrityContinuityEnabled:1;                       //0x9d0
            ULONG AuditLoaderIntegrityContinuity:1;                         //0x9d0
            ULONG EnableModuleTamperingProtection:1;                        //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit:1;               //0x9d0
            ULONG RestrictIndirectBranchPrediction:1;                       //0x9d0
            ULONG IsolateSecurityDomain:1;                                  //0x9d0
        } MitigationFlagsValues;                                            //0x9d0
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x9d4
        struct
        {
            ULONG EnableExportAddressFilter:1;                              //0x9d4
            ULONG AuditExportAddressFilter:1;                               //0x9d4
            ULONG EnableExportAddressFilterPlus:1;                          //0x9d4
            ULONG AuditExportAddressFilterPlus:1;                           //0x9d4
            ULONG EnableRopStackPivot:1;                                    //0x9d4
            ULONG AuditRopStackPivot:1;                                     //0x9d4
            ULONG EnableRopCallerCheck:1;                                   //0x9d4
            ULONG AuditRopCallerCheck:1;                                    //0x9d4
            ULONG EnableRopSimExec:1;                                       //0x9d4
            ULONG AuditRopSimExec:1;                                        //0x9d4
            ULONG EnableImportAddressFilter:1;                              //0x9d4
            ULONG AuditImportAddressFilter:1;                               //0x9d4
            ULONG DisablePageCombine:1;                                     //0x9d4
            ULONG SpeculativeStoreBypassDisable:1;                          //0x9d4
            ULONG CetUserShadowStacks:1;                                    //0x9d4
            ULONG AuditCetUserShadowStacks:1;                               //0x9d4
            ULONG AuditCetUserShadowStacksLogged:1;                         //0x9d4
            ULONG UserCetSetContextIpValidation:1;                          //0x9d4
            ULONG AuditUserCetSetContextIpValidation:1;                     //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged:1;               //0x9d4
            ULONG CetUserShadowStacksStrictMode:1;                          //0x9d4
            ULONG BlockNonCetBinaries:1;                                    //0x9d4
            ULONG BlockNonCetBinariesNonEhcont:1;                           //0x9d4
            ULONG AuditBlockNonCetBinaries:1;                               //0x9d4
            ULONG AuditBlockNonCetBinariesLogged:1;                         //0x9d4
            ULONG Reserved1:1;                                              //0x9d4
            ULONG Reserved2:1;                                              //0x9d4
            ULONG Reserved3:1;                                              //0x9d4
            ULONG Reserved4:1;                                              //0x9d4
            ULONG Reserved5:1;                                              //0x9d4
            ULONG CetDynamicApisOutOfProcOnly:1;                            //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode:1;               //0x9d4
        } MitigationFlags2Values;                                           //0x9d4
    };
    VOID* PartitionObject;                                                  //0x9d8
    ULONGLONG SecurityDomain;                                               //0x9e0
    ULONGLONG ParentSecurityDomain;                                         //0x9e8
    VOID* CoverageSamplerContext;                                           //0x9f0
    VOID* MmHotPatchContext;                                                //0x9f8
    struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;                  //0xa00
    struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                  //0xa08
    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; //0xa10
    ULONG DisabledComponentFlags;                                           //0xa20
    ULONG* volatile PathRedirectionHashes;                                  //0xa28
};
``` 