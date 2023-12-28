WIndows平台下R3（用户态）切换到R0（内核态）系统调用 由一条CPU指令完成：syscall
系统调用主要分为3种形式：
-Int 2EH 
-x86的 sysenter  (sysenter/sysexit 一对配套指令用于快速在R3和R0之间转换的指令）
-x64的 syscall   (syscall/sysret 一对配套指令用于快速在R3和R0之间转换的指令)

-----------------------------------------------------------------------------

syscall基本流程：



伪码（来自Intel手册Vol. 2B 4-689）
==============================================================
IF (CS.L ≠ 1 ) or (IA32_EFER.LMA ≠ 1) or (IA32_EFER.SCE ≠ 1)
(* Not in 64-Bit Mode or SYSCALL/SYSRET not enabled in IA32_EFER *)
THEN #UD;
FI;
RCX := RIP; (* Will contain address of next instruction *)
RIP := IA32_LSTAR;
R11 := RFLAGS;
RFLAGS := RFLAGS AND NOT(IA32_FMASK);
CS.Selector := IA32_STAR[47:32] AND FFFCH (* Operating system provides CS; RPL forced to 0 *)
(* Set rest of CS to a fixed value *)
==============================================================
