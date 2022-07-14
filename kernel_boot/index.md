# linux内核(5.4.81)---内核引导


[发表于看雪论坛](https://bbs.pediy.com/user-839858.htm)

> 本文详细讲解linux内核的加载过程，参考linux-insiders，并结合linux-5.6.6代码对原文的部分老旧内容做修改

# 引导

1. 按下电源开关后, CPU设置寄存器为预定值，程序在实模式下运行，程序首先执行0xfffffff0(映射至ROM)处内容，此处为复位向量，直接跳转至BIOS。

2. BIOS初始化，检查硬件，寻找可引导设备，跳转至引导扇区代码(boot.img)

    + 寻找可引导设备方式: 定位MBR分区, 引导扇区存储在第一个扇区(512字节)的头446字节处。引导扇区以0x55和0xaa(magic bytes)结束。

    + MBR分区代码只占用一个扇区, 空间较小，只执行了一些初始化工作, 然后跳转至GRUB2的core image(以diskboot.img为起始)继续执行。

3. core image的初始化代码将剩余的core image(包含GRUB 2的内核代码和文件系统驱动)加载到内存中，运行grub_main
    + grub_main 初始化控制台，计算模块基地址，设置root设备，读取 grub 配置文件，加载模块等，最后将grub切换为normal模式

    + normal模式调用grub_normal_execute完成最后的准备工作，显示一个菜单列出可用的操作系统。

    + 选择操作系统后grub_menu_execute_entry被调用，用以运行boot命令，引导操作系统, 运行kernel代码
        - 内核自带bootloader，但是新版本内核已经弃用

        - kernel boot protocol规定，bootloader必须具备协议中规定的头信息 

# 实模式运行内核

1. kernel地址(header.S _start)位于X + sizeof(KernelBootSector) + 1

    + 内核加载进入内存后，空间排布 
    ``` 
            | Protected-mode kernel  |
    100000   +------------------------+
            | I/O memory hole        |
    0A0000   +------------------------+
            | Reserved for BIOS      | Leave as much as possible unused
            ~                        ~
            | Command line           | (Can also be below the X+10000 mark)
    X+10000  +------------------------+
            | Stack/heap             | For use by the kernel real-mode code.
    X+08000  +------------------------+
            | Kernel setup           | The kernel real-mode code.
            | Kernel boot sector     | The kernel legacy boot sector.
        X +------------------------+
            | Boot loader            | <- Boot sector entry point 0x7C00
    001000   +------------------------+
            | Reserved for MBR/BIOS  |
    000800   +------------------------+
            | Typically used by MBR  |
    000600   +------------------------+
            | BIOS use only          |
    000000   +------------------------+
    ```
    
    + kernel初始代码功能: 设置段寄存器，堆栈，BSS段，跳转进入main

2. main函数(主要用来填充boot_params参数)

    + main函数解析
        ``` c
        copy_boot_params();
        /* 
        1. 将header.S中定义的hdr拷贝到boot_params结构体的
        struct setup_header hdr中。
        2. 如果内核是通过老的命令行协议运行起来的，那么就更新
        内核的命令行指针(boot_params.hdr.cmd_line_ptr)。
        */
        /* Initialize the early-boot console */
        console_init();
        /*
        根据命令行参数设置串口,例如ttyS0
        */
        if (cmdline_find_option_bool("debug"))
                puts("early console in setup code\n");

        /* End of heap check */
        init_heap();
        /*
        1. stack_end = esp - STACK_SIZE
        2. 如果heap_end大于stack_end，令stack_end=heap_end 
        */
        /* Make sure we have all the proper CPU support */
        /*
        查看当前CPU level，如果低于系统预设的最低CPU level,
        则系统停止运行
        */
        if (validate_cpu()) {
                puts("Unable to boot - please use a kernel appropriate "
                        "for your CPU.\n");
                die();
        }
        /* Tell the BIOS what CPU mode we intend to run in. */
        set_bios_mode();

        /* Detect memory layout */
        /*
        循环执行调用号为0xe820的0x15中断调用，将每次的返回值
        保存在e820entry数组中,每项的成员如下
        * 内存段的起始地址
        * 内存段的大小
        * 内存段的类型（类型可以是reserved, usable等等)。
        */
        detect_memory();
        /* Set keyboard repeat rate (why?) and query the lock flags */
        /*
        1. 通过中断获得键盘状态
        2. 设置键盘的按键检测频率
        */
        keyboard_init();
        
        /* Query Intel SpeedStep (IST) information */
        query_ist();

        /* Query APM information */
        #if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
                query_apm_bios();
        #endif

                /* Query EDD information */
        #if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
                query_edd();
        #endif

        /* Set the video mode */
        /*
        设置屏幕,暂时用不到=。=
        */
        set_video();

        /* Do the last things and invoke protected mode */
        go_to_protected_mode();
        ```

# 内核切换至保护模式

1. mian调用go_to_protected_mode()函数，由实模式切换至保护模式

    + realmode_switch_hook: 如果boot_params.hdr.realmode_swtch
    存在，则跳转执行boot_params.hdr.realmode_swtch(禁用NMI中断),
    否则直接禁用NMI中断(写数据需要时间，所以后面紧跟io_delay实现短暂延迟)

    + enable_a20： 检测a20是否被激活，如果没有则尝试多种方法激活a20，
    激活失败，则系统停止运行

    + set_idt(null_idt为空，使用lidt将null_idt加载入idt寄存器)
        ``` c
        static void setup_idt(void)
        {
                static const struct gdt_ptr null_idt = {0, 0};
                asm volatile("lidtl %0" : : "m" (null_idt));
        }
        ```
    + set_gdt
        - 使用boot_gdt[]数组存储gdt全局表，初始化CS，DS，TSS表项
        ``` c
        /* CS: code, read/execute, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_CS] = GDT_ENTRY(0xc09b, 0, 0xfffff),
		/* DS: data, read/write, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_DS] = GDT_ENTRY(0xc093, 0, 0xfffff),
		/* TSS: 32-bit tss, 104 bytes, base 4096 */
		/* We only have a TSS here to keep Intel VT happy;
		   we don't actually use it for anything. */
		[GDT_ENTRY_BOOT_TSS] = GDT_ENTRY(0x0089, 4096, 103),
        ```
        - 使用static struct gdt_ptr gdt存储gdt全局表大小与地址

        - 使用lgdt将gdt_ptr加载如gdt寄存器

    + protected_mode_jump(boot_params.hdr.code32_start,(u32&boot_params + (ds() << 4));
        - 该函数使用gcc noreturn特性描述
        
        - 传递code32入口地址(0x100000)，与boot_params内容

        - x86_linux内核引导协议规定使用bzImage时，保护模式的内核被重定位至0x100000

2.  保护模式总结

    + gdtr寄存器(48位)存储全局描述符表的基址(32位)与大小(16位)

    + 段寄存器存储段选择子(16位)，包含段描述符在段描述表中的索引，GDT/LDT标志位，RPL请求者优先级(与段描述符中的优先级协同工作)

    + 段描述符(64位)
        ```
        31          24        19      16              7            0
        ------------------------------------------------------------
        |             | |B| |A|       | |   | |0|E|W|A|            |
        | BASE 31:24  |G|/|L|V| LIMIT |P|DPL|S|  TYPE | BASE 23:16 | 4
        |             | |D| |L| 19:16 | |   | |1|C|R|A|            |
        ------------------------------------------------------------
        |                             |                            |
        |        BASE 15:0            |       LIMIT 15:0           | 0
        |                             |                            |
        ------------------------------------------------------------
        ```
       
        + Limit(20位)表示内存段长度

            - G = 0, 内存段的长度按照1 byte进行增长(Limit每增加1，段长度增加1 byte)，最大的内存段长度将是1M bytes；

            - G = 1, 内存段的长度按照4K bytes进行增长(Limit每增加1，段长度增加4K bytes)，最大的内存段长度是4G bytes;

        + Base(32位)表示段基址

        + 40-47位定义内存段类型以及支持的操作

            - S标志(第44位)定义了段类型，S = 0说明这个内存段是一个系统段;S = 1说明这个内存段是一个代码段或者是数据段(堆栈段是一种特殊类型的数据段，堆栈段必须是可以进行读写的段)。
                
                + S = 1的情况下，第43位决定了内存段是数据段还是代码段。如果43位 = 0，说明是一个数据段，否则就是一个代码段。

                + 数据段，第42，41，40位表示的是(E扩展，W可写，A可访问)
                
                + 代码段，第42，41，40位表示的是(C一致，R可读，A可访问）

                ``` 
                                |           Type Field        | Descriptor Type | Description
                |-----------------------------|-----------------|------------------
                | Decimal                     |                 |
                |             0    E    W   A |                 |
                | 0           0    0    0   0 | Data            | Read-Only
                | 1           0    0    0   1 | Data            | Read-Only, accessed
                | 2           0    0    1   0 | Data            | Read/Write
                | 3           0    0    1   1 | Data            | Read/Write, accessed
                | 4           0    1    0   0 | Data            | Read-Only, expand-down
                | 5           0    1    0   1 | Data            | Read-Only, expand-down, accessed
                | 6           0    1    1   0 | Data            | Read/Write, expand-down
                | 7           0    1    1   1 | Data            | Read/Write, expand-down, accessed
                |                  C    R   A |                 |
                | 8           1    0    0   0 | Code            | Execute-Only
                | 9           1    0    0   1 | Code            | Execute-Only, accessed
                | 10          1    0    1   0 | Code            | Execute/Read
                | 11          1    0    1   1 | Code            | Execute/Read, accessed
                | 12          1    1    0   0 | Code            | Execute-Only, conforming
                | 14          1    1    0   1 | Code            | Execute-Only, conforming, accessed
                | 13          1    1    1   0 | Code            | Execute/Read, conforming
                | 15          1    1    1   1 | Code            | Execute/Read, conforming, accessed
                ```

        + P 标志(bit 47) 说明该内存段是否已经存在于内存中。如果P = 0，那么在访问这个内存段的时候将报错。

        + AVL 标志(bit 52) 在Linux内核中没有被使用。

        + L 标志(bit 53) 只对代码段有意义，如果L = 1，说明该代码段需要运行在64位模式下。

        + D/B flag(bit 54) 根据段描述符描述的是一个可执行代码段、下扩数据段还是一个堆栈段，这个标志具有不同的功能。（对于32位代码和数据段，这个标志应该总是设置为1；对于16位代码和数据段，这个标志被设置为0。）。

            - 可执行代码段。此时这个标志称为D标志并用于指出该段中的指令引用有效地址和操作数的默认长度。如果该标志置位，则默认值是32位地址和32位或8位的操作数；如果该标志为0，则默认值是16位地址和16位或8位的操作数。指令前缀0x66可以用来选择非默认值的操作数大小；前缀0x67可用来选择非默认值的地址大小。
        
            - 栈段（由SS寄存器指向的数据段）。此时该标志称为B（Big）标志，用于指明隐含堆栈操作（如PUSH、POP或CALL）时的栈指针大小。如果该标志置位，则使用32位栈指针并存放在ESP寄存器中；如果该标志为0，则使用16位栈指针并存放在SP寄存器中。如果堆栈段被设置成一个下扩数据段，这个B标志也同时指定了堆栈段的上界限。
        
            - 下扩数据段。此时该标志称为B标志，用于指明堆栈段的上界限。如果设置了该标志，则堆栈段的上界限是0xFFFFFFFF（4GB）；如果没有设置该标志，则堆栈段的上界限是0xFFFF（64KB）。

# 内核切换至长模式

1. x86_64架构下code32_start(内核启动时在0x100000处加载，但是如果内核崩溃，需要重新加载内核时，此处会进行重定位) 在head_64.S(使用-fPIC编译，用于适配内核加载地址重定位)中定义

2. head_64.S

    + head_64.S(starup_32) 解析
        
        ``` S
                __HEAD  //宏定义，声名代码段(#define __HEAD  .section  ".head.text","ax")
                .code32
        SYM_FUNC_START(startup_32)
                cld 
                /*
                * Test KEEP_SEGMENTS flag to see if the bootloader is asking
                * us to not reload segments
                */
                /*
                判断loadflags是否设置KEEP_SEGMENTS标志位
                */
                testb $KEEP_SEGMENTS, BP_loadflags(%esi)  
                jnz 1f
                /*
                如果没有设置KEEP_SEGMENTS标志位，则使用DS段描述符初始化数据段寄存器
                */
                cli
                movl	$(__BOOT_DS), %eax
                movl	%eax, %ds
                movl	%eax, %es
                movl	%eax, %ss
        1:

        /*
        * Calculate the delta between where we were compiled to run
        * at and where we were actually loaded at.  This can only be done
        * with a short local call on x86.  Nothing  else will tell us what
        * address we are running at.  The reserved chunk of the real-mode
        * data at 0x1e4 (defined as a scratch field) are used as the stack
        * for this calculation. Only 4 bytes are needed.
        */
        /*
        使用bootparams结构中的scratch作为临时栈顶，call 1f, popl %ebp(将当前物
        理位置置于ebp),通过subl $1b, %ebp 定位startup_32真实地址
        */
                leal	(BP_scratch+4)(%esi), %esp
                call	1f
        1:	popl	%ebp
                subl	$1b, %ebp

        /* setup a stack and make sure cpu supports long mode. */
        /* startup_32基地址结合boot_stack_end 重新设置栈顶
                movl	$boot_stack_end, %eax
                addl	%ebp, %eax
                movl	%eax, %esp
        /*
        调用verify_cpu 判断CPU 是否支持长模式和SSE，如果不支持则不再向长模式跳转
        */
                call	verify_cpu
                testl	%eax, %eax
                jnz	.Lno_longmode
        /*
        * Compute the delta between where we were compiled to run at
        * and where the code will actually run at.
        *
        * %ebp contains the address we are loaded at by the boot loader and %ebx
        * contains the address where we should move the kernel image temporarily
        * for safe in-place decompression.
        */

        #ifdef CONFIG_RELOCATABLE
                movl	%ebp, %ebx
                movl	BP_kernel_alignment(%esi), %eax
                decl	%eax
                addl	%eax, %ebx
                notl	%eax
                andl	%eax, %ebx
                cmpl	$LOAD_PHYSICAL_ADDR, %ebx
                jae	1f
        #endif
                movl	$LOAD_PHYSICAL_ADDR, %ebx
        1:

                /* Target address to relocate to for decompression */
                movl	BP_init_size(%esi), %eax
                subl	$_end, %eax
                addl	%eax, %ebx

        /*
        * Prepare for entering 64 bit mode
        */

                /* Load new GDT with the 64bit segments using 32bit descriptor */
                /* 
                重新加载全局描述表，64位代码段描述项添加 CS.L(长模式标志为) = 1 CS.D = 0
                SYM_DATA_START_LOCAL(gdt)
                        .word	gdt_end - gdt
                        .long	gdt
                        .word	0
                        .quad	0x00cf9a000000ffff	/* __KERNEL32_CS */
                        .quad	0x00af9a000000ffff	/* __KERNEL_CS */
                        .quad	0x00cf92000000ffff	/* __KERNEL_DS */
                        .quad	0x0080890000000000	/* TS descriptor */
                        .quad   0x0000000000000000	/* TS continued */
                SYM_DATA_END_LABEL(gdt, SYM_L_LOCAL, gdt_end)
                */
                
                addl	%ebp, gdt+2(%ebp)
                lgdt	gdt(%ebp)

                /* Enable PAE mode */
                /* cr4寄存器第5位置1,开启PAE模式
                movl	%cr4, %eax
                orl	$X86_CR4_PAE, %eax
                movl	%eax, %cr4

                ... (创建页表) ...

        ```

    + 页表(IA-32e 分页模式)
        
        1. cr3寄存器
        
            ``` 
            63                  52 51                                                       32
            --------------------------------------------------------------------------------
            |                     |                                                          |
            |    Reserved MBZ     |            Address of the top level structure            |
            |                     |                                                          |
            --------------------------------------------------------------------------------
            31                                  12 11            5     4     3 2             0
            --------------------------------------------------------------------------------
            |                                     |               |  P  |  P  |              |
            |  Address of the top level structure |   Reserved    |  C  |  W  |    Reserved  |
            |                                     |               |  D  |  T  |              |
            --------------------------------------------------------------------------------
            ```
            
            - Bits 63:52 - reserved must be 0.
            
            - Bits 51:12 - stores the address of the top level paging structure;
        
            - Bits 11:5 - reserved must be 0;
        
            - Bits 4:3 - PWT or Page-Level Writethrough and PCD or Page-level cache disable indicate. These bits control the way the page or Page Table is handled by the hardware cache;
        
            - Bits 2:0 - ignored;

        2. 页表项

            ``` 
            63  62                  52 51                                                  32
            --------------------------------------------------------------------------------
            | N |                     |                                                     |
            |   |     Available       |     Address of the paging structure on lower level  |
            | X |                     |                                                     |
            --------------------------------------------------------------------------------
            31                                              12 11  9 8 7 6 5   4   3 2 1     0
            --------------------------------------------------------------------------------
            |                                                |     | M |I| | P | P |U|W|    |
            | Address of the paging structure on lower level | AVL | B |G|A| C | W | | |  P |
            |                                                |     | Z |N| | D | T |S|R|    |
            --------------------------------------------------------------------------------
            ```

            - Bits 63 - N/X位(不可执行位)表示被这个页表项映射的所有物理页执行代码的能力；
            
            - Bits 62：52 - CPU忽略，被系统软件使用；
        
            - Bits 51：12 - 存储低级分页结构的物理地址；
        
            - Bits 11：9 - 被 CPU 忽略；
            
            - MBZ - 必须为 0；
        
            - 忽略位；
        
            - A - 访问标志位暗示物理页或者页结构被访问；
        
            - PWT 和 PCD 用于缓存；
            
            - U/S - 普通用户/超级管理员访问标志位 控制被这个页表项映射的所有物理页的访问权限；
        
            - R/W - 读写位 控制被这个页表项映射的所有物理页的读写权限;
        
            - P - 存在位 表示页表或物理页是否被加载进内存；

        3. 线性地址转换为物理地址
        
            - 64位线性地址只有低48位有意义

            - cr3寄存器存储4级页表地址

            - 线性地址中的第39位到第47位存储4级页表项索引，第30位到第38位存储3级页表项索引，第29位到第21位存储2级页表项索引，第12位到第20位存储1级页表项索引，第0位到第11位提供物理页的字节偏移；

    + 继续解析 head_64.S(starup_32)

        ``` S
                /* Enable Long mode in EFER (Extended Feature Enable Register) */
                /* 
                启用拓展寄存器
                */
                movl	$MSR_EFER, %ecx
                rdmsr
                btsl	$_EFER_LME, %eax
                wrmsr
                
                /* After gdt is loaded */
                /*
                初始化LDT寄存器
                */
                xorl	%eax, %eax
                lldt	%ax
                movl    $__BOOT_TSS, %eax
                ltr	%ax

                /*
                * Setup for the jump to 64bit mode
                *
                * When the jump is performend we will be in long mode but
                * in 32bit compatibility mode with EFER.LME = 1, CS.L = 0, CS.D = 1
                * (and in turn EFER.LMA = 1).	To jump into 64bit mode we use
                * the new gdt/idt that has __KERNEL_CS with CS.L = 1.
                * We place all of the values on our mini stack so lret can
                * used to perform that far jump.
                */
                pushl	$__KERNEL_CS
                leal	startup_64(%ebp), %eax
                pushl	%eax

                /* Enter paged protected Mode, activating Long Mode */
                /*
                启用分页机制
                */
                movl	$(X86_CR0_PG | X86_CR0_PE), %eax /* Enable Paging and Protected mode */
                movl	%eax, %cr0

                /* Jump from 32bit compatibility mode into 64bit mode. */
                /*
                cs段选择子(指向cs_kernel_64段描述符)，rip(startup_64物理地址)，已经压入栈中
                */
                lret
                /*
                跳转进入startup_64
                */
        SYM_FUNC_END(startup_32)
        ```

# 长模式下内核解压缩

1. 进入64位长模式后，将数据段寄存器设置为空描述符，以实现寻址平坦化(长模式下段寄存器，段描述符显得有些鸡肋，只保留部分功能) 

2. 如果设置了内核重定位，则首先通过rip相对寻址获得当前代码段加载的基地址，2MB字节对齐后，与LOAD_PHYSICAL_ADDR比较，如果不同，则使用该基地址替换LOAD_PHYSICAL_ADDR(这种操作在startup32中实现过，但是在这里又实现一遍是因为64位引导可以直接跳到startup_64而忽略startup_32)，紧接着将rbx设置为用以解压内核的代码的地址

3. 按照64位引导协议，重置rsp(以rbx为基地址)，flag寄存器，GDT

4. 将压缩内核(位于当前代码与解压缩代码之间)复制到栈上(rbx为基地址)后，跳转到rbx处(用于解压内核的代码段)

5. 因为接下来会执行c语言程序，所以提前清空bss段

6. 调用extract_kernel函数
  
    + 初始化video/console(程序不知道系统引导类型，所以再次初始化)

    + 初始化堆，堆长度为0x10000

    + 调用choose_random_location(用来适配KASLR安全机制)选择可以用来写入已解压内核的物理空间
   
    + 原地解压内核

    + parse_elf函数将内核可加载段加载入choose_random_location的返回地址

    + handle_relocations函数完成到64位内核代码段的跳转

# 至此，x86_64架构下64位linux内核成功运行


