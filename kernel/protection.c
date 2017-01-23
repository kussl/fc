#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/kprobes.h>
#include <linux/sched.h>

/*
Static assumption for the number of processes that will simultaneously ask for disabling mprotect. Ideally this has to be dynamic. 
*/
#define MAX_PROC_IN_F_CODE 400
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
    printk("Checking %lx\n", in_f_code[index].pages[i]);
    if(in_f_code[index].pages[i] <= start &&
      start <= (in_f_code[index].pages[i] + 0x1000)) {
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


/*This one is called from rust_sys_mprotect to handle the case where
a disable only is requested. Subsequent calls with the same key and requested will be ignored.
*/
static void disable_mprotect_only(int pid,unsigned long start, size_t len) {
  int i = is_in_f_mode(pid);

  /*Disable mprotect in future since pid has no previous record. We will regard len as a page to protect. Other pages can be added by subsequent calls.
  */
  if(i == -1) {
    in_f_code[pc].pid = pid;
    in_f_code[pc].key = start;
    in_f_code[pc].pages[in_f_code[pc].pageindex++] = len;
    pc = (pc +1) % MAX_PROC_IN_F_CODE;
  }
  else {
    //A second call will be ignored if with the same key.
    if (start == in_f_code[i].key) {

    }
    //A second call will result in action if the key doesn't match.
    else {
      rust_take_action(start);
    }
  }
}

/*This one is called from rust_sys_mprotect to handle the case where
a enable only is requested. Subsequent calls with the same key and requested will be ignored.
*/
static void enable_mprotect_only(int pid,unsigned long start, size_t len) {
  int i = is_in_f_mode(pid);

  if(i == -1) {
    //Ignore the enable call if no disable preceeded. Also, it won't harm anyone.
  }
  else {
    /*
    pid has called mprotect for disabling before. It's OK to take out pid from the list and remove its protected pages. But if the key (which is the start parameter) does not match the one in records, then take action.
    */
    if (start == in_f_code[i].key) {
      in_f_code[i].pid = -1;
      in_f_code[i].key = -1;
      empty_page_range_for_process(i);
    }
    //Keys don't match, so take action.
    else {
      rust_take_action(start);
    }
  }
}

/*This one is called from rust_sys_mprotect to handle the case where
a disable is requested. Subsequent calls with the same key and requested will result in enabling mprotect and removing the process from the list.
*/
static void disable_and_enable_mprotect(int pid,unsigned long start, size_t len) {
  int i = is_in_f_mode(pid);
  //Disable mprotect in future.
  if(i == -1) {
    in_f_code[pc].pid = pid;
    in_f_code[pc].key = start;
    in_f_code[pc].pages[in_f_code[pc].pageindex++] = len;
    pc = (pc +1) % MAX_PROC_IN_F_CODE ;
  }
  //Re-enable mprotect in future, if the key matches.
  else {
    if (start == in_f_code[i].key) {
        in_f_code[i].pid = -1;
        in_f_code[i].key = -1;
        empty_page_range_for_process(i);
    }
    else {
      //The key does not match.
      rust_take_action(start);
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

  //Both enable and disable mprotect
  if(prot == 0xa00a00a) {
    printk( "%d %s: FC (DIS/ENABLE): %lu len %lx prot %lx \n",
                pid, current->comm,start,len,prot);
    disable_and_enable_mprotect(pid, start, len);
  }
  //Only disable mprotect
  else if(prot == 0xa00a00c) {
    printk( "%d %s: FC (DISABLE): %lu len %lx prot %lx \n",
                pid, current->comm,start,len,prot);
    disable_mprotect_only(pid,start,len);
  }
  //Only enable mprotect
  else if(prot == 0xa00a00d) {
    printk( "%d %s: FC (ENABLE): %lu len %lx prot %lx \n",
                pid, current->comm,start,len,prot);
    enable_mprotect_only(pid,start,len);
  }
  //Receive additional page addresses to protect.
  else if(prot == 0xa00a00b) {
    printk( "%d %s: FC (PAGES): %lu len %lx prot %lx\n",
                pid, current->comm,start,len,prot);
    add_pages_to_protection(pid, start, len);
  }
  //No signal from the process
  else {
    int i = is_in_f_mode(pid);
    if(i> -1) {
      //In protected mode, and a call to mprotect without a protocol call, regard as an alarm
      if (match_page_range(start, i)){
        printk("Start address in forbidden range.\n");
        rust_take_action(start);
      }
    }
  }
	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}


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



static int __init protection_init(void)
{
    printk(KERN_INFO "Fidelius Charm Kernel Assist ==> \n");
    jprobe_init();
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit protection_cleanup(void)
{
    printk(KERN_INFO "Fidelius Charm Kernel Assist <==\n");
    unregister_jprobe(&my_jprobe);
}

module_init(protection_init);
module_exit(protection_cleanup);
