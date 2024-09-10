/*
 * include/asm-xtensa/thread_info.h
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2005 Tensilica Inc.
 */

#ifndef _XTENSA_THREAD_INFO_H
#define _XTENSA_THREAD_INFO_H

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
# include <asm/processor.h>
#endif

/*
 * low level task data that entry.S needs immediate access to
 * - this struct should fit entirely inside of one cache line
 * - this struct shares the supervisor stack pages
 * - if the contents of this structure are changed, the assembly constants
 *   must also be changed
 */

#ifndef __ASSEMBLY__

#if XTENSA_HAVE_COPROCESSORS

typedef struct xtregs_coprocessor {
	xtregs_cp0_t cp0;
	xtregs_cp1_t cp1;
	xtregs_cp2_t cp2;
	xtregs_cp3_t cp3;
	xtregs_cp4_t cp4;
	xtregs_cp5_t cp5;
	xtregs_cp6_t cp6;
	xtregs_cp7_t cp7;
} xtregs_coprocessor_t;

#endif

// thread_info用于存储线程频繁访问的数据，如task_struct、exec_domain、flags、status、cpu等
struct thread_info {
	// task指向task_struct结构体，表示线程对应的进程
	struct task_struct	*task;		/* main task structure */
	// exec_domain指向exec_domain结构体，表示线程的执行域（不同的执行域有不同的系统调用表和信号处理方式）
	struct exec_domain	*exec_domain;	/* execution domain */
	// flags表示线程的低级标志，用于表示线程的各种状态，控制线程的行为
	unsigned long		flags;		/* low level flags */
	// status表示线程的同步状态，通常用于线程间的同步和通信
	unsigned long		status;		/* thread-synchronous flags */
	// 当前线程运行的CPU
	__u32			cpu;		/* current CPU */
	// 抢占计数器，用于表示线程是否可以被抢占（0表示可以被抢占，>0表示不可被抢占）
	__s32			preempt_count;	/* 0 => preemptable,< 0 => BUG*/

	// addr_limit表示线程的地址空间，用于控制线程可以访问的内存地址范围
	mm_segment_t		addr_limit;	/* thread address space */
	// restart_block表示线程的重启系统调用块，用于保存系统调用的相关信息（当系统调用被中断时，可以通过该块恢复系统调用）
	struct restart_block    restart_block;

	// cpenable表示协处理器使能标志，用于表示协处理器是否被启用
	unsigned long		cpenable;

	/* Allocate storage for extra user states and coprocessor states. */
#if XTENSA_HAVE_COPROCESSORS
	xtregs_coprocessor_t	xtregs_cp;
#endif
	// xtregs_user表示用户态寄存器，用于保存用户态寄存器的值
	xtregs_user_t		xtregs_user;
};

#else /* !__ASSEMBLY__ */

/* offsets into the thread_info struct for assembly code access */
#define TI_TASK		 0x00000000
#define TI_EXEC_DOMAIN	 0x00000004
#define TI_FLAGS	 0x00000008
#define TI_STATUS	 0x0000000C
#define TI_CPU		 0x00000010
#define TI_PRE_COUNT	 0x00000014
#define TI_ADDR_LIMIT	 0x00000018
#define TI_RESTART_BLOCK 0x000001C

#endif

#define PREEMPT_ACTIVE		0x10000000

/*
 * macros/functions for gaining access to the thread information structure
 */

#ifndef __ASSEMBLY__

#define INIT_THREAD_INFO(tsk)			\
{						\
	.task		= &tsk,			\
	.exec_domain	= &default_exec_domain,	\
	.flags		= 0,			\
	.cpu		= 0,			\
	.preempt_count	= INIT_PREEMPT_COUNT,	\
	.addr_limit	= KERNEL_DS,		\
	.restart_block = {			\
		.fn = do_no_restart_syscall,	\
	},					\
}

#define init_thread_info	(init_thread_union.thread_info)
#define init_stack		(init_thread_union.stack)

/* how to get the thread information struct from C */
static inline struct thread_info *current_thread_info(void)
{
	struct thread_info *ti;
	 __asm__("extui %0,a1,0,13\n\t"
	         "xor %0, a1, %0" : "=&r" (ti) : );
	return ti;
}

#else /* !__ASSEMBLY__ */

/* how to get the thread information struct from ASM */
#define GET_THREAD_INFO(reg,sp) \
	extui reg, sp, 0, 13; \
	xor   reg, sp, reg
#endif


/*
 * thread information flags
 * - these are process state flags that various assembly files may need to access
 * - pending work-to-be-done flags are in LSW
 * - other flags in MSW
 */
#define TIF_SYSCALL_TRACE	0	/* syscall trace active */
#define TIF_SIGPENDING		1	/* signal pending */
#define TIF_NEED_RESCHED	2	/* rescheduling necessary */
#define TIF_SINGLESTEP		3	/* restore singlestep on return to user mode */
#define TIF_IRET		4	/* return with iret */
#define TIF_MEMDIE		5
#define TIF_RESTORE_SIGMASK	6	/* restore signal mask in do_signal() */
#define TIF_POLLING_NRFLAG	16	/* true if poll_idle() is polling TIF_NEED_RESCHED */
#define TIF_FREEZE		17	/* is freezing for suspend */

#define _TIF_SYSCALL_TRACE	(1<<TIF_SYSCALL_TRACE)
#define _TIF_SIGPENDING		(1<<TIF_SIGPENDING)
#define _TIF_NEED_RESCHED	(1<<TIF_NEED_RESCHED)
#define _TIF_SINGLESTEP		(1<<TIF_SINGLESTEP)
#define _TIF_IRET		(1<<TIF_IRET)
#define _TIF_POLLING_NRFLAG	(1<<TIF_POLLING_NRFLAG)
#define _TIF_RESTORE_SIGMASK	(1<<TIF_RESTORE_SIGMASK)
#define _TIF_FREEZE		(1<<TIF_FREEZE)

#define _TIF_WORK_MASK		0x0000FFFE	/* work to do on interrupt/exception return */
#define _TIF_ALLWORK_MASK	0x0000FFFF	/* work to do on any return to u-space */

/*
 * Thread-synchronous status.
 *
 * This is different from the flags in that nobody else
 * ever touches our thread-synchronous status, so we don't
 * have to worry about atomic accesses.
 */
#define TS_USEDFPU		0x0001	/* FPU was used by this task this quantum (SMP) */

#define THREAD_SIZE 8192	//(2*PAGE_SIZE)
#define THREAD_SIZE_ORDER 1

#endif	/* __KERNEL__ */
#endif	/* _XTENSA_THREAD_INFO */
