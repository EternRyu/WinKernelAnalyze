# Process Environment Block 进程环境块

TEB与PEB这部分fs(x86下)与gs(x64下)段寄存器来完成

R3下FS指向线程环境块(TEB)
在R0下则指向处理器控制区域(KPCR)

PEB获取
x86 FS:[30h] 
x64 GS:[60h]

x64 PEB结构体
<details> 
<summary><font size="4" color="orange">_PEB64结构</font></summary> 
<pre><code class="language-cpp">
~~~
//0x7c8 bytes (sizeof)
struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    ULONGLONG Ldr;                                                          //0x18
    ULONGLONG ProcessParameters;                                            //0x20
    ULONGLONG SubSystemData;                                                //0x28
    ULONGLONG ProcessHeap;                                                  //0x30
    ULONGLONG FastPebLock;                                                  //0x38
    ULONGLONG AtlThunkSListPtr;                                             //0x40
    ULONGLONG IFEOKey;                                                      //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob:1;                                           //0x50
            ULONG ProcessInitializing:1;                                    //0x50
            ULONG ProcessUsingVEH:1;                                        //0x50
            ULONG ProcessUsingVCH:1;                                        //0x50
            ULONG ProcessUsingFTH:1;                                        //0x50
            ULONG ProcessPreviouslyThrottled:1;                             //0x50
            ULONG ProcessCurrentlyThrottled:1;                              //0x50
            ULONG ProcessImagesHotPatched:1;                                //0x50
            ULONG ReservedBits0:24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        ULONGLONG KernelCallbackTable;                                      //0x58
        ULONGLONG UserSharedInfoPtr;                                        //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    ULONGLONG ApiSetMap;                                                    //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    ULONGLONG TlsBitmap;                                                    //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    ULONGLONG ReadOnlySharedMemoryBase;                                     //0x88
    ULONGLONG SharedData;                                                   //0x90
    ULONGLONG ReadOnlyStaticServerData;                                     //0x98
    ULONGLONG AnsiCodePageData;                                             //0xa0
    ULONGLONG OemCodePageData;                                              //0xa8
    ULONGLONG UnicodeCaseTableData;                                         //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    ULONGLONG ProcessHeaps;                                                 //0xf0
    ULONGLONG GdiSharedHandleTable;                                         //0xf8
    ULONGLONG ProcessStarterHelper;                                         //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    ULONGLONG LoaderLock;                                                   //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    ULONGLONG PostProcessInitRoutine;                                       //0x230
    ULONGLONG TlsExpansionBitmap;                                           //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    ULONGLONG pShimData;                                                    //0x2d8
    ULONGLONG AppCompatInfo;                                                //0x2e0
    struct _STRING64 CSDVersion;                                            //0x2e8
    ULONGLONG ActivationContextData;                                        //0x2f8
    ULONGLONG ProcessAssemblyStorageMap;                                    //0x300
    ULONGLONG SystemDefaultActivationContextData;                           //0x308
    ULONGLONG SystemAssemblyStorageMap;                                     //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    ULONGLONG SparePointers[4];                                             //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    ULONGLONG WerRegistrationData;                                          //0x358
    ULONGLONG WerShipAssertPtr;                                             //0x360
    ULONGLONG pUnused;                                                      //0x368
    ULONGLONG pImageHeaderHash;                                             //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x378
            ULONG CritSecTracingEnabled:1;                                  //0x378
            ULONG LibLoaderTracingEnabled:1;                                //0x378
            ULONG SpareTracingBits:29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct LIST_ENTRY64 TppWorkerpList;                                     //0x390
    ULONGLONG WaitOnAddressHashTable[128];                                  //0x3a0
    ULONGLONG TelemetryCoverageHeader;                                      //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    ULONGLONG LeapSecondData;                                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x7c0
            ULONG Reserved:31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
}; 
~~~
</code>
</pre> </details>



<details> 
<summary><font size="4" color="orange">_PEB_LDR_DATA结构</font></summary> 
<pre><code class="language-cpp">
~~~
//0x58 bytes (sizeof)
struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;    模块加载顺序                //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;  模块在内存中的顺序          //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;  模块初始化时的顺序  //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
}; 
~~~
</code>
</pre> </details>


>struct _LIST_ENTRY InLoadOrderModuleList;    模块加载顺序                //0x10
struct _LIST_ENTRY InMemoryOrderModuleList;  模块在内存中的顺序          //0x20
struct _LIST_ENTRY InInitializationOrderModuleList;  模块初始化时的顺序  //0x30
![alt text](ImageFile\LDR_DATA_TABLE_ENTRY.png)

这三个链表链表使用的结构是_LDR_DATA_TABLE_ENTRY</br>
使用该结构解析时需要根据所用的链在的偏移位置进行一定的位移</br>
以达到回到_LDR_DATA_TABLE_ENTRY 结构base的地址正确解析</br>
例如通过InMemoryOrderModuleList链查找</br>
查到的偏移后需要进行-0x10的偏移回到头部</br>
`dt _LDR_DATA_TABLE_ENTRY 0x1d28f962d50-0x10`</br>

<details> 
<summary><font size="4" color="orange">_LDR_DATA_TABLE_ENTRY结构</font></summary> 
<pre><code class="language-cpp">
~~~
//0x120 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;         镜像基址                                         //0x30
    VOID* EntryPoint;      入口点                                           //0x38
    ULONG SizeOfImage;     镜像大小                                         //0x40
    struct _UNICODE_STRING FullDllName;               模块全路径字符串       //0x48
    struct _UNICODE_STRING BaseDllName;               模块名称字符串         //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary:1;                                         //0x68
            ULONG MarkedForRemoval:1;                                       //0x68
            ULONG ImageDll:1;                                               //0x68
            ULONG LoadNotificationsSent:1;                                  //0x68
            ULONG TelemetryEntryProcessed:1;                                //0x68
            ULONG ProcessStaticImport:1;                                    //0x68
            ULONG InLegacyLists:1;                                          //0x68
            ULONG InIndexes:1;                                              //0x68
            ULONG ShimDll:1;                                                //0x68
            ULONG InExceptionTable:1;                                       //0x68
            ULONG ReservedFlags1:2;                                         //0x68
            ULONG LoadInProgress:1;                                         //0x68
            ULONG LoadConfigProcessed:1;                                    //0x68
            ULONG EntryProcessed:1;                                         //0x68
            ULONG ProtectDelayLoad:1;                                       //0x68
            ULONG ReservedFlags3:2;                                         //0x68
            ULONG DontCallForThreads:1;                                     //0x68
            ULONG ProcessAttachCalled:1;                                    //0x68
            ULONG ProcessAttachFailed:1;                                    //0x68
            ULONG CorDeferredValidate:1;                                    //0x68
            ULONG CorImage:1;                                               //0x68
            ULONG DontRelocate:1;                                           //0x68
            ULONG CorILOnly:1;                                              //0x68
            ULONG ChpeImage:1;                                              //0x68
            ULONG ReservedFlags5:2;                                         //0x68
            ULONG Redirected:1;                                             //0x68
            ULONG ReservedFlags6:2;                                         //0x68
            ULONG CompatDatabaseProcessed:1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
}; 
~~~
</code>
</pre> </details>