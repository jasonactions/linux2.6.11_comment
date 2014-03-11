	.file	"asm-offsets.c"
	.text
.globl foo
	.type	foo, @function
foo:
#APP
	
->SIGCONTEXT_eax $44 offsetof(struct sigcontext, eax)
	
->SIGCONTEXT_ebx $32 offsetof(struct sigcontext, ebx)
	
->SIGCONTEXT_ecx $40 offsetof(struct sigcontext, ecx)
	
->SIGCONTEXT_edx $36 offsetof(struct sigcontext, edx)
	
->SIGCONTEXT_esi $20 offsetof(struct sigcontext, esi)
	
->SIGCONTEXT_edi $16 offsetof(struct sigcontext, edi)
	
->SIGCONTEXT_ebp $24 offsetof(struct sigcontext, ebp)
	
->SIGCONTEXT_esp $28 offsetof(struct sigcontext, esp)
	
->SIGCONTEXT_eip $56 offsetof(struct sigcontext, eip)
	
->
	
->CPUINFO_x86 $0 offsetof(struct cpuinfo_x86, x86)
	
->CPUINFO_x86_vendor $1 offsetof(struct cpuinfo_x86, x86_vendor)
	
->CPUINFO_x86_model $2 offsetof(struct cpuinfo_x86, x86_model)
	
->CPUINFO_x86_mask $3 offsetof(struct cpuinfo_x86, x86_mask)
	
->CPUINFO_hard_math $6 offsetof(struct cpuinfo_x86, hard_math)
	
->CPUINFO_cpuid_level $8 offsetof(struct cpuinfo_x86, cpuid_level)
	
->CPUINFO_x86_capability $12 offsetof(struct cpuinfo_x86, x86_capability)
	
->CPUINFO_x86_vendor_id $40 offsetof(struct cpuinfo_x86, x86_vendor_id)
	
->
	
->TI_task $0 offsetof(struct thread_info, task)
	
->TI_exec_domain $4 offsetof(struct thread_info, exec_domain)
	
->TI_flags $8 offsetof(struct thread_info, flags)
	
->TI_status $12 offsetof(struct thread_info, status)
	
->TI_cpu $16 offsetof(struct thread_info, cpu)
	
->TI_preempt_count $20 offsetof(struct thread_info, preempt_count)
	
->TI_addr_limit $24 offsetof(struct thread_info, addr_limit)
	
->TI_restart_block $28 offsetof(struct thread_info, restart_block)
	
->
	
->EXEC_DOMAIN_handler $4 offsetof(struct exec_domain, handler)
	
->RT_SIGFRAME_sigcontext $164 offsetof(struct rt_sigframe, uc.uc_mcontext)
	
->TSS_sysenter_esp0 $-8700 offsetof(struct tss_struct, esp0) - sizeof(struct tss_struct)
	
->PAGE_SIZE_asm $4096 PAGE_SIZE
	
->VSYSCALL_BASE $-8192 __fix_to_virt(FIX_VSYSCALL)
#NO_APP
	ret
	.size	foo, .-foo
	.section	.note.GNU-stack,"",@progbits
	.ident	"GCC: (GNU) 3.4.3"
