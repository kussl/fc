#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/kasan.h>
#include <asm/stacktrace.h>

/*
Static assumption for the number of processes that will simultaneously ask for disabling mprotect. Ideally this has to be dynamic.
*/
#define MAX_PROC_IN_F_CODE 4000
#define MAX_PAGES_ 100

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hussain Almohri");
MODULE_DESCRIPTION("A module for assisting a Rust program to protect its memory by allowing a process to request enabling or disabling mprotect which will assist the process itself to implement the actual memory protection.");



/*
Holds PID, unique key, and page addresses for a process that has requested to disable mprotect.
*/
typedef struct rust_protection {
  int pid;
  unsigned long key;
  unsigned long pages[MAX_PAGES_];
  int pageindex;
  int ret_signal;
  unsigned long rip;
} r_prot;



struct kprobe kp;

/*
in_f_code holds a list of r_prot structures where each member is a process that has requested to disable mprotect on select memory pages but has not yet asked to release mprotect protection.
*/
static r_prot in_f_code[MAX_PROC_IN_F_CODE];
static int pc = 0; //Counter for in_f_code


/*
An action algorithm for those processes that violate will attempt a malicious use of mprotect, which is when a process has disabled mprotect with a key and will issue an mprotect call on a protected page without presenting the key.
*/

static void rust_take_action(unsigned long start) {
  int signum = SIGKILL;
  struct siginfo info;
  int ret;
  memset(&info, 0, sizeof(struct siginfo));
  info.si_signo = signum;
  ret = send_sig_info(signum, &info, current);
  if (ret < 0) {
    printk(KERN_INFO "error sending signal\n");
  } else {
    printk(KERN_INFO "%d %s: killed foreign code trying to mprotect on %lx\n",
        task_pid_nr(current), current->comm, start);
  }
}


/*
Linear search to decide if a process has disabled mprotect.
*/
static int is_in_f_mode(int pid) {
  int i;
  for(i=0; i<pc; i++) {
    if(pid == in_f_code[i].pid) {
      return i;
    }
  }
  return -1;
}

/*
Linear search to decide if a page address is in a list of protected pages for a specific process indicated by the index parameter.
*/
static int match_page_range(unsigned long start, int index) {
  int i;
  for(i=0; i<in_f_code[index].pages[i]; i++) {
    //printk("Checking %lx\n", in_f_code[index].pages[i]);
    if(in_f_code[index].pages[i] <= start &&
      start < (in_f_code[index].pages[i] + 0x1000)) {
        return 1;
      }
  }
  return 0;
}

/*
Releases protected pages for a process once an enable call is issued.
*/
static void empty_page_range_for_process(int index) {
  int i;
  for(i=0; i<in_f_code[index].pages[i]; i++) {
    in_f_code[index].pages[i] = -1;
  }
}



static unsigned long ripvalue(void) {
  struct pt_regs *tregs = task_pt_regs(current);
  return tregs->ip;
}




/*
This one is called from rust_sys_mprotect to handle the case where
a disable only is requested.
The user process must have provided a safe region address and a page address.
The safe region address will be treated as a key. Later when an enable is
requested, the key will be checked against the IP value and the value of the
protected pages (see enable_mprotect_only).
*/
static void disable_mprotect_only(int pid, unsigned long safe_region, unsigned long page_address) {

  //Check if the process is currently in protection. An index of the list of protected processes will be returned or -1 otherwise.
  int i = is_in_f_mode(pid);

  /*
  Disable mprotect in future since pid has no previous record.
  */
  if(i == -1) {
    in_f_code[pc].pid = pid;
    in_f_code[pc].key = safe_region;
    in_f_code[pc].pages[in_f_code[pc].pageindex++] = page_address;
    in_f_code[pc].rip = ripvalue();
    printk("Key recorded: %lx\n", in_f_code[pc].key);
    pc = (pc +1) % MAX_PROC_IN_F_CODE;
  }
  /*
  A disable call for an already protected process is useless.
  */
  else {
    //ignore
  }
}


/*This one is called from rust_sys_mprotect to enable mprotect for the current process. No parameters are required.
*/
static void enable_mprotect_only(int pid, unsigned long RIP) {

  //Find the process' index in the list of protected processes. If -1, the process is not protected; ignore.
  int i = is_in_f_mode(pid);

  if(i == -1) {
    //Ignore the enable call if no disable preceeded. It won't harm anyone.
  }
  else {
    /*
    pid has called mprotect for disabling before. Check if IP is pointing to the safe region address. If so, the call is coming from FC. Otherwise, assume it's malicious. In both cases, empty the process.
    */

    if (RIP == in_f_code[i].key) {
      printk("FC: Key %lx matched. Enabling mprotect..\n", RIP);
      in_f_code[i].pid = -1;
      in_f_code[i].key = -1;
      empty_page_range_for_process(i);
    }
    //Keys don't match, so take action.
    else {
      in_f_code[i].pid = -1;
      in_f_code[i].key = -1;
      empty_page_range_for_process(i);
      printk("FC: Keys don't match: have %lx vs given %lx\n", in_f_code[i].key, RIP);
      rust_take_action(RIP);
    }
  }
}



/*This one is called from rust_sys_mprotect to handle tadditional pages to be added for protection. Subsequent calls with the same key will add the provided page address to the list of proectected pages for the current process.
*/
static void add_pages_to_protection(int pid,unsigned long start, size_t len) {
  int i = is_in_f_mode(pid);
  if (i < 0) {
    //ignore
  }
  else {
    if (in_f_code[i].key == start) {
      in_f_code[i].pages[in_f_code[i].pageindex++] = len;
    }
  }
}

/*
The kernel invokes rust_sys_mprotect whenever a process calls sys_mprotect. rust_sys_mprotect will execute before sys_mprotect which implements a protocol for rust processes to ask enabling/disabling mprotect.
*/

static long rust_sys_mprotect(unsigned long start, size_t len, unsigned long prot) {

  int pid = task_pid_nr(current);
  struct pt_regs *tregs = task_pt_regs(current);

  unsigned long IP = 0;
  unsigned long PAGE = 0;

  if(prot == 0xa00a00c || prot == 0xa00a00d || prot == 0xa00a00b) {
      printk( "%d %s: FC: %lu len %lx prot %lx ip %lx\n",
              pid, current->comm,tregs->bx,tregs->cx,prot,tregs->ip);
      IP = tregs->ip;
      PAGE = tregs->cx;
  }

  //Only disable mprotect
  if(prot == 0xa00a00c) {
    disable_mprotect_only(pid,IP,PAGE);
  }
  //Only enable mprotect
  else if(prot == 0xa00a00d) {
    enable_mprotect_only(pid,IP);
  }
  //Receive additional page addresses to protect.
  else if(prot == 0xa00a00b) {
    add_pages_to_protection(pid, start, len);
  }
  //No signal from the process
  else {
    int i = is_in_f_mode(pid);
    if(i> -1) {
      //In protected mode, and a call to mprotect without a protocol call, regard as an alarm
      if (match_page_range(start, i)){
        printk("Start address in forbidden range\n");
        rust_take_action(start);
      }
    }
  }


	jprobe_return();
	return 0;
}

/*
int kretprobe_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
  int pid = task_pid_nr(current);
  int i = is_in_f_mode(pid);
  int ret_signal = check_ret_signal(i);
  void *stack = task_stack_page(current);
  unsigned long *last = end_of_stack(current);
  //unsigned long retval = regs_return_value(regs);
  struct pt_regs *tregs = task_pt_regs(current);
  long eip = regs->ip;
  long esp = regs->sp;

  unsigned long *ip,*sp;
  ip = (unsigned long *) eip;
  sp = (unsigned long *) esp;


  //A disable signal
  if(ret_signal==1) {
  }
  //An enable signal
  else if (ret_signal==2) {
    printk("Stored rip: 0x%lx\n", in_f_code[i].rip);

    in_f_code[i].pid = -1;
    in_f_code[i].key = -1;
    empty_page_range_for_process(i);
    //printk("FC (RET-2): 0x%lu\n", regs_return_value(regs));
    printk("Original return address: 0x%lx\n", (unsigned long)ri->ret_addr);
    printk("Top of stack: 0x%lx\n", *(unsigned long*)(stack));
    printk("End of stack: 0x%lx\n", *last);
    //printk("current->stack: 0x%lx\n", st);
    printk("EIP: 0x%lx %lx\n", *((unsigned long *)eip), eip);
    printk("ESP: 0x%lx %lx\n", *sp, esp);

    pr_info(" ip = %lx, t-ip = %lx, sp = %lx, t-sp = %lx, flags = 0x%lx\n",
		 regs->ip, tregs->ip, regs->sp, tregs->sp, regs->flags);

  }
  // if( strcmp("web",current->comm) == 0) {
  //   printk("Original return address (read): 0x%lx\n", (unsigned long)ri->ret_addr);
  // }
  return 0;
}*/



/*
Initialize a jprobe to execute rust_sys_mprotect before executing sys_mprotect.
*/
static struct jprobe my_jprobe = {
	.entry			= rust_sys_mprotect,
	.kp = {
		.symbol_name	= "sys_mprotect",
	},
};

static int jprobe_init(void)
{
	int ret;
	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	/*printk(KERN_INFO "Planted jprobe at %p, handler addr %p\n",
	       my_jprobe.kp.addr, my_jprobe.entry);
	       */
	return 0;
}

/*
static struct kretprobe rp = {
  .kp = {
    .symbol_name = "sys_mprotect",
  },
  .handler = kretprobe_handler,
  .maxactive = NR_CPUS,
};


static int kretprobe_init(void) {
  int ret = register_kretprobe(&rp);
  if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n", ret);
		return -1;
	}
  return 0;
} */



static int __init protection_init(void)
{
    printk(KERN_INFO "Fidelius Charm Kernel Assist ==> \n");
    jprobe_init();
    //kretprobe_init();
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit protection_cleanup(void)
{
    printk(KERN_INFO "Fidelius Charm Kernel Assist <==\n");
    unregister_jprobe(&my_jprobe);
    //unregister_kretprobe(&rp);
}

module_init(protection_init);
module_exit(protection_cleanup);
