# Disclaimer

This project has been done under supervision of RedHat reverse engineers. Analysis report is quite complex and there were mutiple students attending Crash(8) course. Imagining the amount of text our supervisors have to read lead me to spicing it up a little...  
  
I'll add relevant memory dump after its authors approval...

# Crashdump analysis write up

Inspector Jacques Pruzo reporting in.  
  
"Na jistem systemu dochazelo k zaseknuti nejruznejsich prikazu"  
"EN: Certain system happens to get stuck when using various commands"  
Inspector Jacques deduction: something isn't right  
  
"ethtool, dhclien, ip"  
Inspector Jacques deduction: something isn't right about this  

"jak presne spravce systemu ziskal onen vmcore"  
"EN: how exactly has system administrator obtain this vmcore"  
Inspection:
```
    crash> set hex
    crash> mod -S module

    crash> bt | head -1
    PID: 10491  TASK: ffff9a6477e0bf40  CPU: 0   COMMAND: "bash"
```
looks like bash crashed the system
```
    crash> ps | grep "RU"
          0      0   0  ffffffff83616480  RU   0.0       0      0  [swapper/0]
    >     0      0   1  ffff9a64794aaf70  RU   0.0       0      0  [swapper/1]
    >     0      0   2  ffff9a64794abf40  RU   0.0       0      0  [swapper/2]
    >     0      0   3  ffff9a64794acf10  RU   0.0       0      0  [swapper/3]
    >     0      0   4  ffff9a64794adee0  RU   0.0       0      0  [swapper/4]
    >     0      0   5  ffff9a64794aeeb0  RU   0.0       0      0  [swapper/5]
    >     0      0   6  ffff9a6479510000  RU   0.0       0      0  [swapper/6]
    >     0      0   7  ffff9a6479510fd0  RU   0.0       0      0  [swapper/7]
         79      2   0  ffff9a6475e60fd0  RU   0.0       0      0  [kworker/0:2]
    > 10491  10486   0  ffff9a6477e0bf40  RU   0.0  115568   2180  bash
```
it seems to be the only non-system process running (notice PID)  
  
now back to the backtrack
```
    #10 [ffff9a63f041fda0] async_page_fault at ffffffff83116798
    #11 [ffff9a63f041fe60] __handle_sysrq at ffffffff82e2f53d
    #12 [ffff9a63f041fe90] write_sysrq_trigger at ffffffff82e2f9af
    #13 [ffff9a63f041fea8] proc_reg_write at ffffffff82c90630
    #14 [ffff9a63f041fec8] vfs_write at ffffffff82c1acd0
    #15 [ffff9a63f041ff08] sys_write at ffffffff82c1baff
    #16 [ffff9a63f041ff50] system_call_fastpath at ffffffff8311f7d5
```
by looking at the sequence now it is obvious, that panic was caused by "trigger"ing it,  
but it wasn't while Jacques was on the case, so let's check it...  
  
as the kernel panicked, it stored all its registers, RIP is relevant to us now  
```
    #10 [ffff9a63f041fda0] async_page_fault at ffffffff83116798
        [exception RIP: sysrq_handle_crash+0x16]
        RIP: ffffffff82e2ed16  RSP: ffff9a63f041fe58  RFLAGS: 00010246


    crash> dis -r ffffffff82e2ed16

    0xffffffff82e2ed00 <sysrq_handle_crash>:        nopl   0x0(%rax,%rax,1) [FTRACE NOP]
    0xffffffff82e2ed05 <sysrq_handle_crash+0x5>:    push   %rbp
    0xffffffff82e2ed06 <sysrq_handle_crash+0x6>:    mov    %rsp,%rbp
    0xffffffff82e2ed09 <sysrq_handle_crash+0x9>:    movl   $0x1,0x814741(%rip)        # 0xffffffff83643454
    0xffffffff82e2ed13 <sysrq_handle_crash+0x13>:   sfence 
    0xffffffff82e2ed16 <sysrq_handle_crash+0x16>:   movb   $0x1,0x0                 <------ NULL dereference
```
this doesn't look very hallal to Inspector Jacques... hardcoded dereferencing NULL
```
	crash> sym sysrq_handle_crash
	ffffffff82e2ed00 (t) sysrq_handle_crash /usr/src/debug/kernel-3.10.0-861.el7/linux-3.10.0-861.el7.PROJECT.v2.x86_64/drivers/tty/sysrq.c: 134
```
Inspector Jacques spotted the killer:
```
    char *killer = NULL;

    ...

    *killer = 1;
```
"proc dochazelo k uvaznuti ruznych sitovych prikazu"  
"EN: why did network utilities cause system to get stuck"  
  
Inspector Jacques assumption: deadlock probably
```
    crash> ps | grep -E "(ip|ethtool|dhclient)$"
      10433   9175   4  ffff9a647594cf10  UN   0.0    7700    556  ethtool
      10462  10439   6  ffff9a6475eedee0  UN   0.1  107368   5132  dhclient
      10485  10468   5  ffff9a6475814f10  UN   0.0    7000    528  ip
```
Alright, all suspended, let's look what's up with them  
  
dhclient  
```
    crash> bt 10462
     #0 [ffff9a64775afac8] __schedule at ffffffff83112444
     #1 [ffff9a64775afb58] schedule_preempt_disabled at ffffffff831139d9
     #2 [ffff9a64775afb68] __mutex_lock_slowpath at ffffffff83111797
     #3 [ffff9a64775afbc8] mutex_lock at ffffffff83110b7f           <----- target function
     #4 [ffff9a64775afbe0] rtnetlink_rcv at ffffffff82ffdff9        <----- caller function
     #5 [ffff9a64775afbf8] netlink_unicast at ffffffff830243c0
     #6 [ffff9a64775afc40] netlink_sendmsg at ffffffff83024768
     #7 [ffff9a64775afcc8] sock_sendmsg at ffffffff82fcc396
     #8 [ffff9a64775afe28] SYSC_sendto at ffffffff82fccaa1
     #9 [ffff9a64775aff40] sys_sendto at ffffffff82fce42e
    #10 [ffff9a64775aff50] system_call_fastpath at ffffffff8311f7d5
```
looks like dhclient locked a mutex, got suspended and never woken up  
let's find out what mutex it was, targeted function sure has a pointer  
to targeted mutex (further refered as the GOOD BOY MUTEX)  
```
    >whatis mutex_lock
    void mutex_lock(struct mutex *);
```
alright Jacques struck again... the good boy got passed as a pointer, that means a caller function  
had to somehow obtain it and pass as an argument  
```
    crash> dis -r ffffffff82ffdff9                      <----- caller function
    0xffffffff82ffdfe0 <rtnetlink_rcv>:     nopl   0x0(%rax,%rax,1) [FTRACE NOP]
    0xffffffff82ffdfe5 <rtnetlink_rcv+0x5>: push   %rbp
    0xffffffff82ffdfe6 <rtnetlink_rcv+0x6>: mov    %rsp,%rbp
    0xffffffff82ffdfe9 <rtnetlink_rcv+0x9>: push   %rbx
    0xffffffff82ffdfea <rtnetlink_rcv+0xa>: mov    %rdi,%rbx
    0xffffffff82ffdfed <rtnetlink_rcv+0xd>: mov    $0xffffffff836fe760,%rdi     <----- hardcoded good boy address
    0xffffffff82ffdff4 <rtnetlink_rcv+0x14>:        callq  0xffffffff83110b60 <mutex_lock>
    0xffffffff82ffdff9 <rtnetlink_rcv+0x19>:        mov    %rbx,%rdi
```
before we plainstupidly check the good boy, let's find out, whether we really called that function with this  
argument... cpu could have done the argument passing somewhere else and then jump to mutex_lock caller  
```
    crash> dis ffffffff82ffdff9 | grep -E "<rtnetlink_rcv+0x14>$"
    crash>
```
nope, we're safe
```
    crash> sym 0xffffffff836fe760
    ffffffff836fe760 (d) rtnl_mutex         <---- good boy

    sh> whatis rtnl_mutex
    struct mutex rtnl_mutex;

    crash> struct mutex rtnl_mutex | head
    struct mutex {
      count = {
        counter = 0xfffffffd        <----- locked
      }, 
      wait_lock = {
        {
          rlock = {
            raw_lock = {
              val = {
                counter = 0x0
```
counter is -3... that sucks  
  
let's check ip now
```
    crash> bt 10485
    PID: 10485  TASK: ffff9a6475814f10  CPU: 5   COMMAND: "ip"
     #0 [ffff9a6477523ac8] __schedule at ffffffff83112444
     #1 [ffff9a6477523b58] schedule_preempt_disabled at ffffffff831139d9
     #2 [ffff9a6477523b68] __mutex_lock_slowpath at ffffffff83111797
     #3 [ffff9a6477523bc8] mutex_lock at ffffffff83110b7f
     #4 [ffff9a6477523be0] rtnetlink_rcv at ffffffff82ffdff9            <----- same caller function
     #5 [ffff9a6477523bf8] netlink_unicast at ffffffff830243c0
     #6 [ffff9a6477523c40] netlink_sendmsg at ffffffff83024768
     #7 [ffff9a6477523cc8] sock_sendmsg at ffffffff82fcc396
     #8 [ffff9a6477523e28] SYSC_sendto at ffffffff82fccaa1
     #9 [ffff9a6477523f40] sys_sendto at ffffffff82fce42e
    #10 [ffff9a6477523f50] system_call_fastpath at ffffffff8311f7d5
```
we can notice that the we ended up the same way here, even offset in caller function is the same,  
that means there is no necessity to check what happened -> the good boy got locked  
  
mutexes are intialized with counter == 1, when a process/thread locks a mutex, it decrements a counter.  
when a counter is < 1 the mutex is not available and locking it causes process(thread) to sleep until  
it's woken up after the mutex gets unlocked... negative counter indicates sleeping processes.  
there (counter == -3) sleeping processes in our case and plus one that is supossed to unlock the good boy,  
but probably fails to do so. what is the third sleeping process? no, it's not ethtool as Jacques thought...  
```
    crash> ps | grep UN
         81      2   2  ffff9a6475e62f70  UN   0.0       0      0  [kworker/2:1]    <----- ???
      10433   9175   4  ffff9a647594cf10  UN   0.0    7700    556  ethtool
      10462  10439   6  ffff9a6475eedee0  UN   0.1  107368   5132  dhclient
      10485  10468   5  ffff9a6475814f10  UN   0.0    7000    528  ip

    crash> bt 81
    PID: 81     TASK: ffff9a6475e62f70  CPU: 2   COMMAND: "kworker/2:1"
     #0 [ffff9a6475ed7ce8] __schedule at ffffffff83112444
     #1 [ffff9a6475ed7d78] schedule_preempt_disabled at ffffffff831139d9
     #2 [ffff9a6475ed7d88] __mutex_lock_slowpath at ffffffff83111797
     #3 [ffff9a6475ed7de8] mutex_lock at ffffffff83110b7f
     #4 [ffff9a6475ed7e00] rtnl_lock at ffffffff82ffd385                <----- caller function

    crash> dis -r ffffffff82ffd385
    0xffffffff82ffd370 <rtnl_lock>: nopl   0x0(%rax,%rax,1) [FTRACE NOP]
    0xffffffff82ffd375 <rtnl_lock+0x5>:     push   %rbp
    0xffffffff82ffd376 <rtnl_lock+0x6>:     mov    $0xffffffff836fe760,%rdi     <----- its the good boy
    0xffffffff82ffd37d <rtnl_lock+0xd>:     mov    %rsp,%rbp
    0xffffffff82ffd380 <rtnl_lock+0x10>:    callq  0xffffffff83110b60 <mutex_lock>
```
Inspector Jacques identified all vimctims, however killer in not caught... yet  
  
things to remember - the good boy got locked by ip, dhclient and kworker and (possibly) someone else  
  
now from something completely differet - ethclient
```
    crash> bt 10433
    PID: 10433  TASK: ffff9a647594cf10  CPU: 4   COMMAND: "ethtool"
     #0 [ffff9a63f949fa78] __schedule at ffffffff83112444
     #1 [ffff9a63f949fb08] schedule_preempt_disabled at ffffffff831139d9
     #2 [ffff9a63f949fb18] __mutex_lock_slowpath at ffffffff83111797
     #3 [ffff9a63f949fb78] mutex_lock at ffffffff83110b7f                       <----- target function
     #4 [ffff9a63f949fb90] e1000_release_eeprom at ffffffffc018b51c [e1000]     <----- caller function
     #5 [ffff9a63f949fbb0] e1000_read_eeprom at ffffffffc018e475 [e1000]
     #6 [ffff9a63f949fbf0] e1000_get_eeprom at ffffffffc01931b9 [e1000]
     #7 [ffff9a63f949fc48] ethtool_get_any_eeprom at ffffffff82ff3d4f
     #8 [ffff9a63f949fcb0] dev_ethtool at ffffffff82ff5762
     #9 [ffff9a63f949fd98] dev_ioctl at ffffffff83006bdf
    #10 [ffff9a63f949fe28] sock_do_ioctl at ffffffff82fca4bd
    #11 [ffff9a63f949fe50] sock_ioctl at ffffffff82fca6c8
    #12 [ffff9a63f949fe80] do_vfs_ioctl at ffffffff82c2fb90
    #13 [ffff9a63f949ff00] sys_ioctl at ffffffff82c2fe41
    #14 [ffff9a63f949ff50] system_call_fastpath at ffffffff8311f7d5
```
mutex got locked... let's get the address from caller function
```
    crash> dis -r ffffffffc018b51c | tail
    0xffffffffc018b4f6 <e1000_release_eeprom+0x46>: mov    $0xffffffffc019d180,%rdi
    0xffffffffc018b4fd <e1000_release_eeprom+0x4d>: callq  0xffffffff83110b00 <mutex_unlock>
    0xffffffffc018b502 <e1000_release_eeprom+0x52>: pop    %rbx
    0xffffffffc018b503 <e1000_release_eeprom+0x53>: pop    %r12
    0xffffffffc018b505 <e1000_release_eeprom+0x55>: pop    %rbp
    0xffffffffc018b506 <e1000_release_eeprom+0x56>: retq   
    0xffffffffc018b507 <e1000_release_eeprom+0x57>: nopw   0x0(%rax,%rax,1)
    0xffffffffc018b510 <e1000_release_eeprom+0x60>: mov    $0xffffffffc019d180,%rdi         <----- target mutex
    0xffffffffc018b517 <e1000_release_eeprom+0x67>: callq  0xffffffff83110b60 <mutex_lock>
    0xffffffffc018b51c <e1000_release_eeprom+0x6c>: jmp    0xffffffffc018b4dc <e1000_release_eeprom+0x2c>
```
again, let's check whether this argument really got passed
```
    crash> dis e1000_release_eeprom | grep -E "<e1000_release_eeprom+0x(60|67)>$"
    crash>
```
alright we're safe
```
    crash> sym 0xffffffffc019d180
    ffffffffc019d180 (d) e1000_eeprom_lock [e1000]

    crash> struct mutex e1000_eeprom_lock | head
    struct mutex {
      count = {
        counter = 0xffffffff
      }, 
      wait_lock = {
        {
          rlock = {
            raw_lock = {
              val = {
                counter = 0x0
```
hmm diffrent mutex (further refered as the BAD BOY MUTEX) and the counter is -1,  
this means ethtool is the only victim here, let's find the murderer  
  
is the caller function messing with the bad boy?  
```
    crash> dis e1000_release_eeprom | grep 0xffffffffc019d180
    0xffffffffc018b4f6 <e1000_release_eeprom+0x46>: mov    $0xffffffffc019d180,%rdi     <---- bad boy
    0xffffffffc018b510 <e1000_release_eeprom+0x60>: mov    $0xffffffffc019d180,%rdi     <---- bad boy
```
looks like it does...
```
    crash> dis -r e1000_release_eeprom+0x67
    0xffffffffc018b4b0 <e1000_release_eeprom>:      nopl   0x0(%rax,%rax,1) [FTRACE NOP]

    ...         <---- [1]

    0xffffffffc018b4f6 <e1000_release_eeprom+0x46>: mov    $0xffffffffc019d180,%rdi
    0xffffffffc018b4fd <e1000_release_eeprom+0x4d>: callq  0xffffffff83110b00 <mutex_unlock>    <---- unlock
    0xffffffffc018b502 <e1000_release_eeprom+0x52>: pop    %rbx
    0xffffffffc018b503 <e1000_release_eeprom+0x53>: pop    %r12
    0xffffffffc018b505 <e1000_release_eeprom+0x55>: pop    %rbp
    0xffffffffc018b506 <e1000_release_eeprom+0x56>: retq                                        <----- return
    0xffffffffc018b507 <e1000_release_eeprom+0x57>: nopw   0x0(%rax,%rax,1)
    0xffffffffc018b510 <e1000_release_eeprom+0x60>: mov    $0xffffffffc019d180,%rdi
    0xffffffffc018b517 <e1000_release_eeprom+0x67>: callq  0xffffffff83110b60 <mutex_lock>      <----- lock
```
is it possible, that bad boy should have gotten unlocked and it didnt?  
there are few jumps in "... [1]", however they are irrelevant, since every unlocking  
ends up with returning from the function and since we HAVE called locking function it is ovious we didn't unlock  
anything. alright, let's just remember for now, that bad boy got locked here and that was the only thing that happend to him.  
there are two possibilities now -> either bad boy commited suicide (locked himself twice in the same process)  
or someone put him to sleep.  
  
let's check the caller of a caller function
```
     #3 [ffff9a63f949fb78] mutex_lock at ffffffff83110b7f                           <---- target function
     #4 [ffff9a63f949fb90] e1000_release_eeprom at ffffffffc018b51c [e1000]         <---- caller function
     #5 [ffff9a63f949fbb0] e1000_read_eeprom at ffffffffc018e475 [e1000]            <---- caller caller function

    crash> dis e1000_read_eeprom | grep 0xffffffffc019d180
    0xffffffffc018e3ce <e1000_read_eeprom+0x1e>:    mov    $0xffffffffc019d180,%rdi
    0xffffffffc018e409 <e1000_read_eeprom+0x59>:    mov    $0xffffffffc019d180,%rdi
```
looks like it messes with the bad boy
```
    crash> dis e1000_read_eeprom | head -30

    ...             <---- no jumps

    0xffffffffc018e3ce <e1000_read_eeprom+0x1e>:    mov    $0xffffffffc019d180,%rdi
    0xffffffffc018e3d5 <e1000_read_eeprom+0x25>:    sub    $0x8,%rsp
    0xffffffffc018e3d9 <e1000_read_eeprom+0x29>:    mov    %si,-0x2c(%rbp)                      <---- no jumps till here
    0xffffffffc018e3dd <e1000_read_eeprom+0x2d>:    callq  0xffffffff83110b60 <mutex_lock>      <---- mutex SURELY gets locked [1]
    0xffffffffc018e3e2 <e1000_read_eeprom+0x32>:    cmpl   $0x9,0x18(%rbx)                      <---- [3]
    0xffffffffc018e3e6 <e1000_read_eeprom+0x36>:    je     0xffffffffc018e480 <e1000_read_eeprom+0xd0>
    0xffffffffc018e3ec <e1000_read_eeprom+0x3c>:    movzwl 0x54(%rbx),%r15d
    0xffffffffc018e3f1 <e1000_read_eeprom+0x41>:    cmp    %r15w,%r12w                          <---- [3]
    0xffffffffc018e3f5 <e1000_read_eeprom+0x45>:    jb     0xffffffffc018e430 <e1000_read_eeprom+0x80>
    0xffffffffc018e3f7 <e1000_read_eeprom+0x47>:    testb  $0x4,0xf7cc(%rip)                    <---- [3]
    0xffffffffc018e3fe <e1000_read_eeprom+0x4e>:    jne    0xffffffffc018e5bd <e1000_read_eeprom+0x20d>
    0xffffffffc018e404 <e1000_read_eeprom+0x54>:    mov    $0xffffffff,%ebx
    0xffffffffc018e409 <e1000_read_eeprom+0x59>:    mov    $0xffffffffc019d180,%rdi
    0xffffffffc018e410 <e1000_read_eeprom+0x60>:    callq  0xffffffff83110b00 <mutex_unlock>    <---- unlock [3]
    0xffffffffc018e415 <e1000_read_eeprom+0x65>:    add    $0x8,%rsp
    0xffffffffc018e419 <e1000_read_eeprom+0x69>:    mov    %ebx,%eax
    0xffffffffc018e41b <e1000_read_eeprom+0x6b>:    pop    %rbx
    0xffffffffc018e41c <e1000_read_eeprom+0x6c>:    pop    %r12
```
alright, now the hard part... does it get unlocked [3] after the lock [1]?  
  
comparsions before jumps [3] look crackable...first we check wheter it has any point to study them
```
    crash> dis e1000_read_eeprom | grep -E "<e1000_read_eeprom\+0x(36|3c|41|45|47|4e|54|59|60)>$"
    0xffffffffc018e440 <e1000_read_eeprom+0x90>:    jg     0xffffffffc018e3f7 <e1000_read_eeprom+0x47>
    0xffffffffc018e446 <e1000_read_eeprom+0x96>:    je     0xffffffffc018e3f7 <e1000_read_eeprom+0x47>
    0xffffffffc018e455 <e1000_read_eeprom+0xa5>:    jne    0xffffffffc018e404 <e1000_read_eeprom+0x54>
    0xffffffffc018e475 <e1000_read_eeprom+0xc5>:    jmp    0xffffffffc018e409 <e1000_read_eeprom+0x59>
    0xffffffffc018e4a7 <e1000_read_eeprom+0xf7>:    jmpq   0xffffffffc018e409 <e1000_read_eeprom+0x59>
    0xffffffffc018e5b8 <e1000_read_eeprom+0x208>:   jmpq   0xffffffffc018e409 <e1000_read_eeprom+0x59>
    0xffffffffc018e5e5 <e1000_read_eeprom+0x235>:   jmpq   0xffffffffc018e404 <e1000_read_eeprom+0x54>
```
god damnit...  
let's check the source code
```

    crash> sym ffffffffc018e475
    ffffffffc018e475 (T) e1000_read_eeprom+0xc5 [e1000] /usr/src/debug/kernel-3.10.0-861.el7/linux-3.10.0-861.el7.PROJECT.v2.x86_64/
    drivers/net/ethernet/intel/e1000/e1000_hw.c: 3986

    s32 e1000_read_eeprom(struct e1000_hw *hw, u16 offset, u16 words, u16 *data)                                                                                                                         
    {                                                                                                                                                                                                    
        s32 ret;                                                                                                                                                                                         

        mutex_lock(&e1000_eeprom_lock);                                                                                                                                                                  
        ret = e1000_do_read_eeprom(hw, offset, words, data);    <----- [0]
        mutex_unlock(&e1000_eeprom_lock);                                                                                                                                                                
        return ret;                                                                                                                                                                                      
    }

    static s32 e1000_do_read_eeprom(struct e1000_hw *hw, u16 offset, u16 words, u16 *data)
    {
        if (???) {                  <----- [1]
            ...
            return xxx;
        }
        ...

        if (***) {
            ...                     <----- [2] no return here
        }

        e1000_release_eeprom(hw);   <----- [3] ffffffffc018e475 3986

        return status;
    }
```
since 3986th line is inside e1000_do_read_eeprom and there is no stack frame of this function on stack we can  
surely say, that this function was inlined. the e1000_read_eeprom locks bad boy and then "jumps at" (enters)  
the e1000_do_read_eeprom code.  
  
the overall structure of this function is pretty simple -> if (???) do {!!!} and return, if (???) do ... and so on.  
this explains all those jumps in e1000_read_eeprom function. at the end we can see the call that locks bad boy  
under certain circumstances, nested_mutex != 0 [4]  
```
static void e1000_release_eeprom(struct e1000_hw *hw)
{
    ...

    if(nested_mutex)        <----- [4]
        mutex_lock(&e1000_eeprom_lock);

    ...
}
```
Inspector Jacques deduction:  
cpu enters e1000_read_eeprom, lock bad boy for the first time, then "jumps" to the e1000_do_read_eeprom code [0]. here it  
surely doesn't take the branches that end with return xxx [1] since we DID end up at the bottom calling e1000_release_eeprom [3].  
after cpu called e1000_release_eeprom it made a check for nested_mutex and since it was valid it locked bad boy the second time,  
however this doen't imply that there was no unlocking inbetween the calls.  
  
Inspector Jacques assumption:  
either there was no unlocking inbetween the locks or something failed to turn off the nested_mutex flag. or it simply didn't
fail implying that Inspector's analysis was a complete waste of time and making Inspector shoot his brain out...  
  
Inspector Jacques task:  
check all branches of type [2], whether they mess with bad boy or nested_mutex flag  
  
let's focus on e1000_do_read_eeprom from another perspective  
```
static s32 e1000_do_read_eeprom(struct e1000_hw *hw, u16 offset, u16 words, u16 *data)
{
    struct e1000_eeprom_info *eeprom = &hw->eeprom;

    ...         <----- no *eeprom modification

    if (eeprom->type == e1000_eeprom_spi) {                         <---- decision based on type
        
        ...

    } else if (eeprom->type == e1000_eeprom_microwire) {            <---- decision based on type
        
        ...

    }

    e1000_release_eeprom(hw);

    ...
}
```
arguments of e1000_do_read_eeprom are the same as e1000_read_eeprom, so maybe we can read them somehow.  
Jacques is also willing to pay God for type not matching any of the options...  
```
     #5 [ffff9a63f949fbb0] e1000_read_eeprom at ffffffffc018e475 [e1000]    <---- target function [1]
     #6 [ffff9a63f949fbf0] e1000_get_eeprom at ffffffffc01931b9 [e1000]     <---- caller function [2]
     #7 [ffff9a63f949fc48] ethtool_get_any_eeprom at ffffffff82ff3d4f       <---- caller caller function RET [3]

    crash> dis -r ffffffffc01931b9 | tail                                   <---- caller function [2]
    0xffffffffc0193197 <e1000_get_eeprom+0xc7>: jle    0xffffffffc01931c0 <e1000_get_eeprom+0xf0>
    0xffffffffc0193199 <e1000_get_eeprom+0xc9>: movzwl %r15w,%eax
    0xffffffffc019319d <e1000_get_eeprom+0xcd>: lea    (%r14,%r15,1),%esi
    0xffffffffc01931a1 <e1000_get_eeprom+0xd1>: mov    -0x30(%rbp),%rdi     <---- first argument [4]
    0xffffffffc01931a5 <e1000_get_eeprom+0xd5>: lea    (%r12,%rax,2),%rcx
    0xffffffffc01931a9 <e1000_get_eeprom+0xd9>: mov    $0x1,%edx
    0xffffffffc01931ae <e1000_get_eeprom+0xde>: mov    %r15d,%r13d
    0xffffffffc01931b1 <e1000_get_eeprom+0xe1>: movzwl %si,%esi
    0xffffffffc01931b4 <e1000_get_eeprom+0xe4>: callq  0xffffffffc018e3b0 <e1000_read_eeprom>   <---- target
```
let's read the value of -0x30(%rbp) [4] from stack (check for messing with rbp or not pushing it as first  
register... everything ok). we want to read RBP of e1000_get_eeprom [2] that means we have to find  
caller caller RET return value [3]  
  
the stack looks like this
```
   -
  ...
| RBP |     <---- [4]
| RET |     <---- caller caller function return address [3]
| ... |
   +
```
```
    crash> bt -f 10433

    ...

        ffff9a63f949fbe8: ffff9a63f949fc40 <----- [3] ffffffffc01931b9 <----- [4]
     #6 [ffff9a63f949fbf0] e1000_get_eeprom at ffffffffc01931b9 [e1000]
```
we calculate the address of first argument and read it
```
RBP - 0x30 == ffff9a63f949fc10

    crash> rd ffff9a63f949fc10
    ffff9a63f949fc10:  ffff9a63fb438c90         <------ first argument, struct e1000_hw *hw
```
finaly the damned type...
```
    crash> struct e1000_hw ffff9a63fb438c90
    ...
    eeprom = {
        type = e1000_eeprom_microwire,          <------ god damnit
        word_size = 0x40, 
        opcode_bits = 0x3, 
        address_bits = 0x6, 
        delay_usec = 0x32, 
        page_size = 0x0
    }
```
alright let's check the e1000_do_read_eeprom's branch...
```
    ...
    else if (eeprom->type == e1000_eeprom_microwire) {
        for (i = 0; i < words; i++) {
            /* Send the READ command (opcode + addr)  */
            e1000_shift_out_ee_bits(hw,                     <---- not messing with bad boy / nested_mutex
                EEPROM_READ_OPCODE_MICROWIRE,                                                                                                                                                
                eeprom->opcode_bits);
            e1000_shift_out_ee_bits(hw, (u16)(offset + i),  
                eeprom->address_bits);                                                                                                                                                       

            /* Read the data.  For microwire, each word requires the                                                                                                                                 
            * overhead of eeprom setup and tear-down.
            */
            data[i] = e1000_shift_in_ee_bits(hw, 16);                                                                                                                                                
            e1000_standby_eeprom(hw);                       <---- not messing
            cond_resched();                                 <---- this has been pain, but seems alright
        }
    }
```
now we know that either someone screwed up the algorithm or accidently turned on nested_mutex flag  
  
let's hunt for the nested_mutex flag first... e1000_release_eeprom and e1000_read_eeprom are already  
analyzed, we need to search above  
```
    crash> dis e1000_get_eeprom | grep nested
    0xffffffffc0193115 <e1000_get_eeprom+69>:   mov    %al,0xbd69(%rip)        # 0xffffffffc019ee84 <nested_mutex>
```
this looks haram...
```
    crash> sym e1000_get_eeprom
    ffffffffc01930d0 (t) e1000_get_eeprom [e1000] /usr/src/debug/kernel-3.10.0-861.el7/linux-3.10.0-861.el7.PROJECT.v2.x86_64/
    drivers/net/ethernet/intel/e1000/e1000_ethtool.c: 445

    static int e1000_get_eeprom(struct net_device *netdev, struct ethtool_eeprom *eeprom, u8 *bytes)
    {
        ...

        nested_mutex = *bytes       <---- sneaky little killer

        ...

        memcpy(bytes, (u8 *)eeprom_buff + (eeprom->offset & 1), eeprom->len);

        ...
    }
```
there is nothing that a nested_mutex flag and number of bites to copy have in common... wiping the killer soves the problem.  
  
the only one mystery left is - who put kworker, ip and dhclient to sleep?  
  
the good boy (rtnl_mutex) is used for various purposes, one of them is serialization of user apis to network configuration.
one of these apis is ioctl api - the murderer.  
  
most likely ethtool process locked good boy, commited suicide by locking  
bad boy twice and therefore failing to unlock the good boy  
  
Inspector Jacques task:  
dig through source code of every function of ethtools backtrack and look for anything suspicious
```
    crash> bt 10433

        ...

     #8 [ffff9a63f949fcb0] dev_ethtool at ffffffff82ff5762
     #9 [ffff9a63f949fd98] dev_ioctl at ffffffff83006bdf

        ...

    crash> sym ffffffff83006bdf
    ffffffff83006bdf (T) dev_ioctl+0x1cf /usr/src/debug/kernel-3.10.0-861.el7/linux-3.10.0-861.el7.PROJECT.v2.x86_64/net/core/dev_ioctl.c: 458

    int dev_ioctl(struct net *net, unsigned int cmd, void __user *arg)
    {
        ...

        rtnl_lock();
        ret = dev_ethtool(net, &ifr);       <---- suicide
        rtnl_unlock();

        ...
    }
```
there we go!!!  
  
dam dam... dam dam... da dam da dam da dam da daaaaaaaaaaaaaaaam.... da da da dam...  
  
```
                                                         ......,......                                                 
                                                 ..,,,,,,,,,.,,*,,****,...                                             
                                             ..*,,,*,,,,,.,,,,,*,*,,,,,*,,.                                            
                                            ,,*,,**,,,,,,,,,,.,,,,,,,,,,,,,,.                                          
                                          ***,,,*****,**,***,**,,**,,,*,,,***                                          
                                         .,,,..,*,*,,,,,***,,**,*****,,,,,,,,,                                         
                                       ...,..,,****,**////**,,,,**,**/*****,,,,.                                       
                                      .....,,,,,******/*,*,,,,,***,****,***,,...                                       
                                    ......,,***,*/*****,,,,*,,,*****///*,,,,,,....                                     
                                   ....,,,,,*,,,**,,,,.,,****,,,**,,,,,*/*****,...                                     
                                  ..,,,*****,,,*,,,,**,,**,,,******,,**/**,****,,,.                                    
                                 ..,,,,***,,,,*,,*/**////////**//*/**/////,***,,,,*.                                   
                                .....*/,,,***//(##%%&&&&%%&&&%%%%%%&&%&%%##//*****,.                                   
                               ....,*////(%%&&%(((/****,*****,*,**///*****//(#%%#(*,,                                  
                               ,..*/(#%&(/*,..,,,,..,,,,..,,..,,,,............*(%%(*..                               
                              ...*%%/,,.,,.....,,..,,,...........................,*#*,.                              
                             .*#%(,.......,.......,.,...,..........................  . .,.                             
                            ,/#,........,,,,,*,,,,,,,,,***,,,,**,,,,,**,,,.,,..,..... .                                
                          .*(/....*,**/(((((((((((####(####%#################(((#(#(((/****,,..                        
                          **..,**/((#%&%%%%##########%%%%%%%%&&&&&&&&&&&&&&&&&&&&&&&&&&&%%%#((/*.                      
                        ..*/((#%%&@&&%#///////////(((((((//////(((((#######(((#######&&&&&&&&&%(/.                     
                      .,*/((%&@&@&&%%(///////////////(((((((////////((((////((((####(%&&&&&&&&&%#/.                    
                    ..**/#&&&&@&&&&//////****///#%&&&&%%%#(((///////////////(((((((%&&&&&&&&&%%/.                    
                 .,*((%&&@&&&&&&&&%#////*******/((///((#(#%%###///*****//(%&&&%%((///%&&&&&&&&&*.                    
                .*((%%&&&@&&&&&&&#(/*******,*********/////////**,****/(#%&&&&&&//&&&&&&&&&%%/.                     
               .*(#%%&&&&&&&&&&&&&%%/*******,***,*//(##/*/(#(/////*,,*/(((((((((##%((&&&&&&&&/,                      
               ,/#%&&&&&&&%&@@&&&%%#/**,,,,,,,**/((**((%,.*/((////*,,*/((((/((#(**/(%&&&&&&&/*                       
               *(%%&&&&&&(///#&&&%((/**,,,,,,********//*,*///,,****,,*/((/%#%/.*#(*#&&&&&&&%#*                         
               */%&&&&&,//*/%&%(##/,,,,,,,,,,,,,,,*//////,,,,,,*,...,*///#(,*/(/*%&&&&&%%/*                          
               ,*#%&&&&%(#(/**(#((#(*,,,,...........,,,,***,,,,,,,.....*///((//*///&&&&&/.                           
               .,/#%&&&&(((****###(/*,...............,,,,,.....,,,.. ..****//*****/&&&&%#*.                            
                 .(#&&&&&/(*/((//(//*..........................,,..   .*,,****,,,,*%&/.                              
                  ,(#%&&&((//#/*,***................,..........,..    .*,,,,,,,..,*%%#.                                
                   .(%&&&%///(**,,........,,,,,,,,,.........,,,,,.    .,,,,,,,,,,,(#*                                  
                    ./%&&&//*//**,........,,,,,,,,,.......,*,.....   ..,,,,,,,**,,,                                    
                      .#%##*//,,,,.........,,,,,,.......,*,,,**,,,*****,*,,,,****,                 .,**,..             
                       ./%%%,,,,,.........,,,,.........,,..,*/(/**/////***,,,***,,            ,*#&&@@@@@@@@%/,         
                         .#&(,,...........,,.........,,.  ..,**///////*,**,,,***,.         *(%&&&@@@@&%#(((#&&%/       
                          ./&/*.........................,**///(((///*,,,,,,***.       /&@&&&&&%*.            .(*     
                           *&&&(/,......................,*/((#(((/(////*.,,,,,,,      (&@@@&&&*.                 /#.   
                            .*%/**,,.................,*//((##((((////((#*,,,,,,,    .%@@@@@%/                     ,%   
                              *//*,,,,,.............,***////////***////#(/,,,,,,   (&@@@@%/          .            .%/  
                               ,****,,...............,,///((//(#%%%##(//((*,,,.   #@@@@&,             ..           /%* 
                                .///*,,..............,,,.......,,,,,*/////*,,,  .(@@@@(,                           /&/ 
                                 .///**,..........,,,,....,,,**/***,,,****,,,.  #&&@@(         ..                  (&/ 
                                  .*((/,,.......,,,.....,,,***//******,**,,..  *&&&&%         .....               .%%* 
                                    *(#(/,...........,,,,,***********,,,,,.   *%&&&*       ......                ./&*  
                                     */##/,,,,,..........,,....,,,,*,,,,,.    %@&&%      ........                (%%.  
                                       ,(#/*,,,,,....................,,,.    .&@&&/     ......                  ,&&/   
                                         ,#(/**,,,,,.........,.......,,.     .&@@&.    ......                  .%&%    
                                           .*/////,,,,,,,,********,,,,.      .&@@%     ......                 #&@/.    
                                             .*/////*,,************,,         %@@%       .......            *#@@(      
                                              ..//(//////////*****.           *%@&.       ......           /@@&(       
                                            .. ...,*////////////*.             .&@/         .           ,%@@%/         
                                             ...... .*//////////,.              ./&,                  *#&&&/           
                                              .........*///////*.                 .#(.             ,/%&&%,.            
                                               .....   ..,**/*/,                    .%%(,.   .,*(%&&&%/,               
                                                  ...         ,/,                      .#@&&&&@@%/,                    
                                           ,(#(*.   ..       .*##*                      ,&@@&@.                      
                                        .(%%%&&&&/           /#%#/,       ,*.        .,*(###########(.                 
                                     .*((/////(%#*          ,&&&(*/.      ,(*      .,(%%%%%%%%%%%%%###(,               
                                  ,*/*,........,.          /%&&%((%(,       ..  ..*(#%%%%%%%%%%%%%%%%%#/               
                               ,,*,,..         .            ,&#%&(*,.      .,,/(%&&&%%%%&&&&&%&%%%%%/.               
                            .,*,,..                          ,(#%##*.     .,(#%&&&&&&&&&&&&&&&&&%(/.                 
                         .,,,...             .                 (&%(#(/,   ,**#&&&&&&&&@@@&&&&&%%%%%*.                  
                                            .                   ,/%&%(/.**((#%&&&&@&&&&&&&&%%%%%%###(.                 
                                                                 ./%%#(/((((#%%&&&&&&&&&%%%%%%%%%%###.                 
                                                                  .////(######%%&&&%%%%%%%%%%&&&%%%#/                  
                                                                  .//(##(((%%&&&%&&&&&&&&&&&&&&&&/,                    
                                         .                       .((((##((%%%&&&%%%&&%%&&&&&@@&&&%(                    
                                                                ,/((####%%%&&&&&&%%&&&&&@&&&&&&&%%#/.                  
                                                                /((###%%&&&&&&&&&&&%%&&&&&&%%%%%%%%/.                  
                                                              .(####%&&&&@@&&&&%%&&&&%%%%%%%&%%%%%%/.                  
                                                             ,//(##&&&&&&&&&&&&&%%%&&&%&&&&&&&&&*                    
                                                           .,//(##&&&&&&&&&&&&&&%%%%&&&&&&&&&&&@&*.                    
                                                          ,(###%%&&&&@@&&&&@@@&&&&&&&&&&&&&&&&%%%#/                    
                                             .         .(%#%%%&&&&@@@&&&@@@@@@@@&&%&&%%%%%%%%%%%%#*                    
```