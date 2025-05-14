## VT 虚拟化技术

系统Ring

Ring 3 用户层</br>
Ring 0 内核层</br>
Ring -1 VT</br>
Ring -2 SMM （System Management Mode）Intel在它的CPU里专门留了个模式叫，拥有最高的权限</br>
Ring -3 IME  Intel ME 是 Intel Management Engine 的简称 Intel ME 是指 Intel 芯片中一个独立于CPU和操作系统的微处理器。ME里面有用于远程管理的功能，在出现严重漏洞的时可以在不受用户操控下远程管理企业计算机



![alt text](ImageFile\VM.png)

## VT启动需要的准备
虚拟机的上限数量是CPU的核心数

>The VMCS data are organized into six logical groups:
>
>1.`Guest-state area`. Processor state is saved into the guest-state area on VM exits and loaded from there on VM entries.
>
>2.`Host-state area`. Processor state is loaded from the host-state area on VM exits.
>
>3.`VM-execution control fields`. These fields control processor behavior in VMX non-root operation. They determine in part the causes of VM exits.
>
>4.`VM-exit control fields`. These fields control VM exits.
>
>5.`VM-entry control fields`. These fields control VM entries.
>
>6.`VM-exit information fields`. These fields receive information on VM exits and describe the cause and the nature of VM exits. On some processors, these fields are read-only.4


>VMXON:开启 VMX 模式,可以执行后续的虚拟化相关指令。</br>
>VMXOFF:关闭 VMX 模式，后续虚拟化指令的执行都会失败。</br>
>VMLAUNCH:启动 VMCS指向的虚拟机 Guest OS。</br>
>VMRESUME:从 Hypervisor 中恢复虚拟机 Guest OS 的执行。</br>
>VMPTRLD:激活一块 VMCS,修改处理器当前 VMCS 指针为传入的 VMCS 物理地址。</br>
>VMCLEAR:使一块 VMCS 变为非激活状态，更新处理器当前 VMCS 指针为空。</br>
>VMPTRST:将 VMCS 存储到指定位置。</br>
>VMREAD:读取当前 VMCS 中的数据。</br>
>VMWRITE:向当前 VMCS 中写入数据。</br>
>VMCALL:Guest OS 和 Hypervisor 交互指令，Guest OS 会产生 #VMExit 而陷入 Hypervisor。</br>
>INVEPT:使 TLB 中缓存的地址映射失效。</br>
>INVVPID:使某个 VPID 所对应的地址映射失效。</br>



## Cr0 & Cr4

```c++
union Cr4 {
  ULONG_PTR all;
  struct {
    unsigned vme : 1;         //!< [0] Virtual Mode Extensions
    unsigned pvi : 1;         //!< [1] Protected-Mode Virtual Interrupts
    unsigned tsd : 1;         //!< [2] Time Stamp Disable
    unsigned de : 1;          //!< [3] Debugging Extensions
    unsigned pse : 1;         //!< [4] Page Size Extensions
    unsigned pae : 1;         //!< [5] Physical Address Extension
    unsigned mce : 1;         //!< [6] Machine-Check Enable
    unsigned pge : 1;         //!< [7] Page Global Enable
    unsigned pce : 1;         //!< [8] Performance-Monitoring Counter Enable
    unsigned osfxsr : 1;      //!< [9] OS Support for FXSAVE/FXRSTOR
    unsigned osxmmexcpt : 1;  //!< [10] OS Support for Unmasked SIMD Exceptions
    unsigned reserved1 : 2;   //!< [11:12]
    unsigned vmxe : 1;        //!< [13] Virtual Machine Extensions Enabled
    unsigned smxe : 1;        //!< [14] SMX-Enable Bit
    unsigned reserved2 : 2;   //!< [15:16]
    unsigned pcide : 1;       //!< [17] PCID Enable
    unsigned osxsave : 1;  //!< [18] XSAVE and Processor Extended States-Enable
    unsigned reserved3 : 1;  //!< [19]
    unsigned smep : 1;  //!< [20] Supervisor Mode Execution Protection Enable
    unsigned smap : 1;  //!< [21] Supervisor Mode Access Protection Enable
  } fields;
};


union Cr0 {
  ULONG_PTR all;
  struct {
    unsigned pe : 1;          //!< [0] Protected Mode Enabled
    unsigned mp : 1;          //!< [1] Monitor Coprocessor FLAG
    unsigned em : 1;          //!< [2] Emulate FLAG
    unsigned ts : 1;          //!< [3] Task Switched FLAG
    unsigned et : 1;          //!< [4] Extension Type FLAG
    unsigned ne : 1;          //!< [5] Numeric Error
    unsigned reserved1 : 10;  //!< [6:15]
    unsigned wp : 1;          //!< [16] Write Protect
    unsigned reserved2 : 1;   //!< [17]
    unsigned am : 1;          //!< [18] Alignment Mask
    unsigned reserved3 : 10;  //!< [19:28]
    unsigned nw : 1;          //!< [29] Not Write-Through
    unsigned cd : 1;          //!< [30] Cache Disable
    unsigned pg : 1;          //!< [31] Paging Enabled
  } fields;
};
```

需要开启VMXE
VMXE(VMX-Enable Bit (bit 13 of CR4)) VT

## EPT 内存虚拟