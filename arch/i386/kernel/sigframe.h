/**
 * 调用用户态信号处理函数时，向用户态栈帧中保存的数据
 */
struct sigframe
{
	/**
	 * 信号处理函数的返回地址。它指向__kernel_sigreturn标记处的代码。
	 * 当然，这段代码是在用户态执行的。
	 * xie.baoyou注：linux是如何将__kernel_sigreturn的地址让用户态程序识别到的呢？？
	 */
	char *pretcode;
	/**
	 * 信号编号，信号处理函数需要这个参数
	 */
	int sig;
	/**
	 * 它包含切换到内核态前，用户态进程硬件上下文。
	 * 注意：是第一次进入内核态时，用户态的硬件上下文，所以用户态处理程序弄坏这个环境也不怕，最多是用户态程序崩溃。
	 * 而不会影响内核的稳定性。
	 * 这也是必须是异常和中断返回用户态前才处理信号的原因之一。不能是其他地方。
	 * 看来信号处理函数得小心了，不要把栈弄坏了，否则，应用程序的正常执行流程可能被破坏。
	 */
	struct sigcontext sc;
	/**
	 * 存放用户态进程的浮点寄存器的内容。
	 */
	struct _fpstate fpstate;
	/**
	 * 被阻塞的实时信号位图。
	 */
	unsigned long extramask[_NSIG_WORDS-1];
	/**
	 * 发出sigreturn系统调用的8字节代码。在早期版本中，它还有用。但在2.6中，它仅被当做一个标记来使用。
	 * 以便调试程序能够识别出信号栈帧。
	 */
	char retcode[8];
};

struct rt_sigframe
{
	char *pretcode;
	int sig;
	struct siginfo *pinfo;
	void *puc;
	struct siginfo info;
	struct ucontext uc;
	struct _fpstate fpstate;
	char retcode[8];
};
