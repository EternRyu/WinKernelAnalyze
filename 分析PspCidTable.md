# PspCidTable 
```版本win10 22h2 (Windows 10 19041 x64)```

全局句柄表
里面存储了进程和线程的对象信息。 通过句柄表也可以遍历出隐藏的进程。也就是说全局句柄表里面存储的并不是句柄而是进程EPROCESS和线程ETHREAD

### 定位句柄表
在内核中有一个变量，变量叫做PspCidTable这个变量是未导出的变量
通过对PsLookupProcessByProcessId函数进行分析，其函数栈如下：

PsLookupProcessByProcessId
-> PspReferenceCidTableEntry 
-> ExpLookupHandleTableEntry

#### nt!PsLookupProcessByProcessId:
```
fffff802`3fa656d5 56                   push    rsi
fffff802`3fa656d6 4883ec20             sub     rsp, 20h
fffff802`3fa656da 48897c2438           mov     qword ptr [rsp+38h], rdi
fffff802`3fa656df 488bf2               mov     rsi, rdx
fffff802`3fa656e2 65488b3c2588010000   mov     rdi, qword ptr gs:[188h]
fffff802`3fa656eb 66ff8fe6010000       dec     word ptr [rdi+1E6h]
fffff802`3fa656f2 b203                 mov     dl, 3
fffff802`3fa656f4 e8a7010000           call    ntkrnlmp!PspReferenceCidTableEntry (fffff8023fa658a0)
```

#### nt!PspReferenceCidTableEntry:
```
fffff802`3fa658a0 48895c2408     mov     qword ptr [rsp+8], rbx
fffff802`3fa658a5 48896c2410     mov     qword ptr [rsp+10h], rbp
fffff802`3fa658aa 4889742418     mov     qword ptr [rsp+18h], rsi
fffff802`3fa658af 48897c2420     mov     qword ptr [rsp+20h], rdi
fffff802`3fa658b4 4156           push    r14
fffff802`3fa658b6 4883ec40       sub     rsp, 40h
fffff802`3fa658ba 488b050f0d6a00 mov     rax, qword ptr [ntkrnlmp!PspCidTable (fffff802401065d0)]
fffff802`3fa658c1 0fb6ea         movzx   ebp, dl
fffff802`3fa658c4 f7c1fc030000   test    ecx, 3FCh
fffff802`3fa658ca 0f8470010000   je      ntkrnlmp!PspReferenceCidTableEntry+0x1a0 (fffff8023fa65a40)
fffff802`3fa658d0 488bd1         mov     rdx, rcx
fffff802`3fa658d3 488bc8         mov     rcx, rax
fffff802`3fa658d6 e8d518fcff     call    ntkrnlmp!ExpLookupHandleTableEntry (fffff8023fa271b0)
```
#### nt!ExpLookupHandleTableEntry:
```
mov     eax, [rcx]      ; PspCidTable
PAGE:000000014061D1B2                 and     rdx, 0FFFFFFFFFFFFFFFCh ; 获取除低两位外的Pid/Handle
PAGE:000000014061D1B6                 cmp     rdx, rax        ; 判断Pid/Handle是否=< 句柄表地址
PAGE:000000014061D1B9                 jnb     short return
PAGE:000000014061D1BB                 mov     r8, [rcx+8]     ; (_HANDLE_TABLE*)PspCidTable+0x8->(ULONGLONG)TableCode;
PAGE:000000014061D1BF                 mov     eax, r8d
PAGE:000000014061D1C2                 and     eax, 3          ; eax = TableCode & 3
PAGE:000000014061D1C5                 cmp     eax, 1          ; 是否为01 二级索引表
PAGE:000000014061D1C8                 jnz     short to_cmp_first ; 判断eax是否为零 即一级表
PAGE:000000014061D1CA                 mov     rax, rdx
PAGE:000000014061D1CD                 shr     rax, 0Ah
PAGE:000000014061D1D1                 and     edx, 3FFh
PAGE:000000014061D1D7                 mov     rax, [r8+rax*8-1]
PAGE:000000014061D1DC                 lea     rax, [rax+rdx*4]
PAGE:000000014061D1E0                 retn
PAGE:000000014061D1E0 ; ---------------------------------------------------------------------------
PAGE:000000014061D1E1                 align 2
PAGE:000000014061D1E2
PAGE:000000014061D1E2 to_cmp_first:                           ; CODE XREF: ExpLookupHandleTableEntry+18↑j
PAGE:000000014061D1E2                 test    eax, eax        ; 判断eax是否为零 即一级表
PAGE:000000014061D1E4                 jnz     short third_table ; 不为零
PAGE:000000014061D1E6                 lea     rax, [r8+rdx*4]
PAGE:000000014061D1EA                 retn
PAGE:000000014061D1EA ; ---------------------------------------------------------------------------
PAGE:000000014061D1EB                 align 4
PAGE:000000014061D1EC
PAGE:000000014061D1EC third_table:                            ; CODE XREF: ExpLookupHandleTableEntry+34↑j
PAGE:000000014061D1EC                 mov     rcx, rdx
PAGE:000000014061D1EF                 shr     rcx, 0Ah
PAGE:000000014061D1F3                 mov     rax, rcx
PAGE:000000014061D1F6                 and     ecx, 1FFh
PAGE:000000014061D1FC                 shr     rax, 9
PAGE:000000014061D200                 and     edx, 3FFh
PAGE:000000014061D206                 mov     rax, [r8+rax*8-2]
PAGE:000000014061D20B                 mov     rax, [rax+rcx*8]
PAGE:000000014061D20F                 lea     rax, [rax+rdx*4]
PAGE:000000014061D213                 retn
PAGE:000000014061D213 ; ---------------------------------------------------------------------------
PAGE:000000014061D214                 db 0CCh
PAGE:000000014061D215 ; ---------------------------------------------------------------------------
PAGE:000000014061D215
PAGE:000000014061D215 return:                                 ; CODE XREF: ExpLookupHandleTableEntry+9↑j
PAGE:000000014061D215                 xor     eax, eax
PAGE:000000014061D217                 retn
```
PspCidTable是一个指向类型为_HANDLE_TABLE的指针
TableCode就是全局句柄表的地址
<details> 
<summary><font size="4" color="orange">_HANDLE_TABLE</font></summary> 
<pre><code class="language-cpp">
//0x80 bytes (sizeof)
struct _HANDLE_TABLE
{
    ULONG NextHandleNeedingPool;      //下一次句柄表扩展的起始句柄索引         //0x0
    LONG ExtraInfoPages;               //审计信息所占用的页面数量            //0x4
    volatile ULONGLONG TableCode;      //指向句柄表的结构                     //0x8
    struct _EPROCESS* QuotaProcess;   //句柄表的内存资源记录在此进程中        //0x10
    struct _LIST_ENTRY HandleTableList; //所有的句柄表形成一个链表(这个成员域用来指向下一个句柄表节点的)，链表头为全局变量HandleTableListHead  //0x18
    ULONG UniqueProcessId; //创建进程的ID，用于回调函数                       //0x28
    union
    {
        ULONG Flags;       //标志域                                         //0x2c
        struct
        {
            UCHAR StrictFIFO:1; //是否使用FIFO风格的重用，即先释放还是先重用  //0x2c
            UCHAR EnableHandleExceptions:1;                                 //0x2c
            UCHAR Rundown:1;                                                //0x2c
            UCHAR Duplicated:1;                                             //0x2c
            UCHAR RaiseUMExceptionOnInvalidHandleClose:1;                   //0x2c
        };
    };
    struct _EX_PUSH_LOCK HandleContentionEvent;//若在访问句柄时发生竞争，则在此推锁上阻塞等待 //0x30
    struct _EX_PUSH_LOCK HandleTableLock;   //句柄表锁 仅在句柄表扩展时使     //0x38
    union
    {
        struct _HANDLE_TABLE_FREE_LIST FreeLists[1];//空闲链表表头的句柄索引 //0x40
        struct
        {
            UCHAR ActualEntry[32];                                          //0x40
            struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;                     //0x60
        };
    };
}; 
</code>
</pre> </details>

关于该表信息
|操作|指向的表级|附加|
|---|---|---|
|(TableCode & 3) == 0|该指针所指句柄表为一级句柄表|TableCode的二进制低两位是00，指向一个加密的对象地址 一级表每16bytes才有一次数据|
|(TableCode & 3) == 1|该指针所指句柄表为二级句柄表|TableCode的二进制低两位为01，此表中表项指向一级句柄表 每隔8bytes都有一次数据|
|(TableCode & 3) == 2|该指针所指句柄表为三级句柄表|TableCode的二进制低两位为10，此表中的表项指向二级句柄表 每隔8bytes都有一次数据|

三级表->二级表->一级表

### 一级表
一个表大小为4096Bytes

```_HANDLE_TABLE_ENTRY //0x10 bytes (sizeof)```

一个表有4096\sizeof(_HANDLE_TABLE_ENTRY)=4096\16=256个表项

按照windows ```句柄号是4的整数倍```方式管理进程的话,那么一个表内只能存储 256 / 4 = 40个进程

一级表根据Pid或Handle获得指针的计算得到表项
```
and     rdx, 0FFFFFFFFFFFFFFFCh ;(pid/Handle) & 0FFFFFFFFFFFFFFFCh
lea     rax, [r8+rdx*4]
```

TableCode(抹掉低两位) 形成的指针 直接指向的就是 句柄表存储结构(_HANDLE_TABLE_ENRY)
64位下的 _HANDLE_TABLE_ENTRY 大小是16个字节。32位则是八个字节


<details> 
<summary><font size="4" color="orange">_HANDLE_TABLE_ENTRY</font></summary> 
<pre><code class="language-cpp">
//0x10 bytes (sizeof)
union _HANDLE_TABLE_ENTRY
{
    volatile LONGLONG VolatileLowValue;                                     //0x0
    LONGLONG LowValue;                                                      //0x0
    struct
    {
        struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;   //对象信息    //0x0
    LONGLONG HighValue;                                                     //0x8
    union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;                         //0x8
        struct _EXHANDLE LeafHandleValue;                                   //0x8
    };
    LONGLONG RefCountField;                                                 //0x0
    ULONGLONG Unlocked:1;                                                   //0x0
    ULONGLONG RefCnt:16;                                                    //0x0
    ULONGLONG Attributes:3;                                                 //0x0
    struct
    {
        ULONGLONG ObjectPointerBits:44;                                     //0x0
    ULONG GrantedAccessBits:25;                    //当前句柄的权限          //0x8
    ULONG NoRightsUpgrade:1;                                                //0x8
        ULONG Spare1:6;                                                     //0x8
    };
    ULONG Spare2;                                                           //0xc
}; 
</code>
</pre> </details>

### 二级表
(TableCode & 3) == 1 则为二层结构

表项数量为4096 / 8 = 512项

1层表能存储40个进程 那么二级表能存储512 * 40 大小的进程(20480)

二级表获取一级表项当中内容计算方式:
```
and     rdx, 0FFFFFFFFFFFFFFFCh ;(pid/Handle) & 0FFFFFFFFFFFFFFFCh
mov     rax, rdx
shr     rax, 0Ah            ;右移10bit获得Mid.index
and     edx, 3FFh           ;计算句柄项的Low.index时需要与上0x3ff
mov     rax, [r8+rax*8-1]
lea     rax, [rax+rdx*4]
```

例：
```
ffffb98d6fafd001 一个二级表
ffffb98d6fafd000 最后两位置零就是该表的其实地址
里面的项是一级表的指针

1: kd> dqs ffffb98d6fafd000
ffffb98d`6fafd000  ffffb98d`6bcc8000
ffffb98d`6fafd008  ffffb98d`6fafe000
ffffb98d`6fafd010  ffffb98d`705eb000
ffffb98d`6fafd018  ffffb98d`70fbd000
ffffb98d`6fafd020  ffffb98d`71bff000
ffffb98d`6fafd028  ffffb98d`71f74000
ffffb98d`6fafd030  00000000`00000000
ffffb98d`6fafd038  00000000`00000000

1: kd> dqs ffffb98d`6bcc8000
ffffb98d`6bcc8000  00000000`00000000
ffffb98d`6bcc8008  00000000`00000000
ffffb98d`6bcc8010  8004a667`b040ff95
ffffb98d`6bcc8018  00000000`00000000
ffffb98d`6bcc8020  8004aada`22c0fedd
ffffb98d`6bcc8028  00000000`00000000
ffffb98d`6bcc8030  8004a673`56000001
ffffb98d`6bcc8038  00000000`00000000
ffffb98d`6bcc8040  8004a674`60800001
ffffb98d`6bcc8048  00000000`00000000
ffffb98d`6bcc8050  8004a672`40800001
ffffb98d`6bcc8058  00000000`00000000
ffffb98d`6bcc8060  8004a679`b0800001
ffffb98d`6bcc8068  00000000`00000000
ffffb98d`6bcc8070  8004a67d`61400001
ffffb98d`6bcc8078  00000000`00000000

```

### 三级表
三层结构和二层结构一样

当(TableCode & 3) == 2时

TableCode指向的是一个三维数组指针，它能存储512项二维数组指针

存储项数量

_HANDLE_TABLE_ENTRY (512 * 512 * 4 的进程.)

三级表项获取一级表项当中内容的计算方式:
```
and     rdx, 0FFFFFFFFFFFFFFFCh ;(pid/Handle) & 0FFFFFFFFFFFFFFFCh
mov     rcx, rdx
shr     rcx, 0Ah
mov     rax, rcx
and     ecx, 1FFh
shr     rax, 9
and     edx, 3FFh
mov     rax, [r8+rax*8-2]
mov     rax, [rax+rcx*8]
lea     rax, [rax+rdx*4]
```

## _HANDLE_TABLE_ENTRY

_HANDLE_TABLE_ENTRY->infoTable 是内核对象 如EPROCESS ETHREAT
句柄表项infoTable的不能直接读取（不直接映射对象头，而是间接进行映射？）

该项的的计算方式在win10 22h2下  PspReferenceCidTableEntry函数当中为
```
mov     rdi, [rsi]
sar     rdi, 10h
and     rdi, 0FFFFFFFFFFFFFFF0h

即
((infoTable >> 0x10) & 0xFFFFFFFFFFFFFFF0ui64)
```

拿上面的win10下的句柄对象,计算得到的EPROCESS地址举例
只需要对象结构 -sizeof(OBJECT_HEADER)结构大小
即-0x30看到实际的OBJECT_HEADER结构
```
_OBJECT_HEADER与Body并不是整个object的全部，实际上在object header前面还有optional headers与pool header，一个完全的windows object应该是这样的：

_POOL_HEADER
_OBJECT_QUOTA_CHARGES (optional)
_OBJECT_HANDLE_DB (optional)
_OBJECT_NAME (optional)
_OBJECT_CREATOR_INFO (optional)
_OBJECT_HEADER
body
```
### _OBJECT_HEADER的TypeIndex字段

>_OBJECT_TYPE
在win7之前的windows版本中存在一个Type字段其包含了一个指针指向一个_OBJECT_TYPE结构体，在新版本中，这个字段变为了TypeIndex，其包含了一个全局数组nt!ObTypeIndexTable的索引，而这个数组中存着不同类型的结构体的指针

在windows10中，处于安全考虑，TypeIndex字段被使用异或加密,
通过逆向未导出的API  ObGetObjectType() 来进行分析
```
lea     rax, [rcx-30h]
movzx   ecx, byte ptr [rcx-18h]
shr     rax, 8
movzx   eax, al
xor     rax, rcx
movzx   ecx, byte ptr cs:ObHeaderCookie
xor     rax, rcx
lea     rcx, ObTypeIndexTable
mov     rax, [rcx+rax*8]

即
ObTypeIndexTable[TypeIndex ^ ((OBJECT_HEADERADDR >> 8) & 0XFF ) ^ ObHeaderCookie];
```
如EPROCESS对象的TypeIndex为7

可以通过nt!ObTypeIndexTable[0x7]来获取指向其_OBJECT_TYPE的指针

>InfoMask
在_OBJECT_HEADER->InfoMask中使用掩码的方式来表示哪些可选头存在
内核中存在一个数组ObpInfoMaskToOffset，我们可以根据InfoMask我们可以计算出一个数值作为数组的索引，从而获取我们想要的optional header距离object header的偏移

Offset = ObpInfoMaskToOffset[OBJECT_HEADER->InfoMask & (DesiredHeaderBit	(DesiredHeaderBit-1))]