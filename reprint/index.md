# 一些思考




> 一些思考, 转眼间, 入坑安全已经两年, 一些心得

## 2017-2018学年(大一)

+ 2017年进入大学, 学习土木工程专业, 如果没有后面不知缘由的对计算机的热爱, 或许我现在正在朝着桥梁设计建造工程师这个方向迈进

+ 大一的时候喜欢看大国工匠, 内心热血, 总想做些什么, 却发现自己什么都做不了

+ 在通识课上, 第一次接触c语言, 由此写出了人生中的第一行hello world

+ 奇怪的是, 我并没有想着要用c语言去完成什么高大上的项目, 自己告诉自己, 我只是想知道为什么hello world可以被输出

+ 那几个月天天抱着一本厚厚的c语言去研究, 这也算是我的计算机启蒙了吧

+ 但是我还是不知道为什么hello world可以被输出?

+ 再后来对这个问题答案的渴求促使我转专业(即使降级也要转专业), 我不想和这个问题擦肩而过(或许那个时候, 如果有人可以和我说懂这个问题, 我就可以在土木安心呆着了呢 =.=)

+ 接下来就是准备转专业, 开始转专业, 降级转网安成功(顺便遇到了我可爱的女朋友 >。<)

## 2018-2019学年(还是大一)

+ 带着2017年的问题, 我进入网安, 接触了二进制, 我坚信学习这个方向可以解决我的疑惑

+ 于是2018年的那个秋天, 捧着汇编, 程序员的自我修养度日, 三个月后颤颤巍巍的拿到第一个栈溢出shell, 似懂非懂, 浑浑噩噩, 有拿到shell的喜悦, 但疑惑加深了, 我还是没有解决我的问题, 仿佛陷入死胡同, 而且三个月才学会第一个栈溢出, 这很明显是傻子行为

+ 不是很服气, 于是二刷程序员的自我修养, 这一次好像懂了些什么(elf文件结构, 动态链接, 静态链接, 堆栈布局), 又好像什么都不懂, 总感觉有些东西没有抓住(另外出现了一个新的问题: 进程与进程之间的内存为什么不会产生冲突, 明明汇编会访问相同的地址)

+ 带着疑问, 继续学习栈溢出, 利用技巧花里胡哨, 简直是神仙打架, 遇到问题, 解决问题, 解决不了问题, 自闭几天, 再去解决问题, 磕磕绊绊的也算是把利用技巧全部复现了一遍

+ 赌气似的三刷程序员的自我修养, 很明显这次我懂了更多的东西, 于是回过头整理了一遍栈溢出, 这次出奇的顺利, 没有任何阻碍, 我想或许这段时间我确实进步了

+ 格式化字符串顺利的学完

+ 堆溢出, 不得不说, 我的基础能力菜的出奇, 一个chunk结构体, 一个fastbin单链表以我当时的能力确实看不懂

+ 自闭数星期

+ 再次学习堆溢出, 还是劝退

+ 自闭数星期

+ 耐着性子, 掠过基础知识, 直接接触fastbin attack利用, 云里雾里不知所云, 但按照模式还是可以勉强做题的, 但我想, 这不是我想要的, 我并不是为了做题才选择二进制, 我是为了学习更多的原理, 乃至于到最后解决我的疑惑才选择的二进制

+ 下了很大的决心之后, 决定看ptmalloc源码, 一行一行看, 一个宏定义一个宏定义的看, 一个变量一个变量的看, 一遍不行就再看二遍, 三遍 ...

+ 夏天了, 终于懂了ptmalloc原理, 不过这只是堆溢出利用的起始, 原本以为接下来会是一番更加艰难的探索, 没成想, 好像突然开窍了, 原本各种各样的堆溢出利用方法在我看来异常优雅, 而更让人开心的是, 有很多利用方式都在我阅读源码期间的脑海中闪现过, 于是学习利用技巧变成了复现自己的一些想法

+ 开心没多久, 即使我不愿意也不得不承认, 我学到的东西正在从我脑海中一点一点忘却, 更可怕的是为了获得这些知识, 我曾花费了半年的时间去探索

+ 决定写文章去记录自己的所得, 这样就不会在以后忘记他们

+ 于是写下了linux漏洞利用思维导图

## 2019-2020(大二)

+ 开学之后, 非常幸运的加入了0x401_Team, 在这里找到了一群志同道合的朋友, 一起打ctf, 虽然我还是很菜

+ 2019年的下半年在打ctf中度过, 同时增加了ptmalloc源码分析, 堆溢出demo这两篇文章

+ 冬天, 疫情, 2020上半年在家里度过

+ 带着对hello_world内在原理与进程间内存为什么不会互相影响的疑惑, 开始探索内核

+ 搭建环境, 编译busybox, 编译内核, 虽然在现在看来, 不到一个小时就能完成的事情, 硬是被我搞成了一个星期

+ 刚开始的内核学习非常顺利, rop, 任意读写, 堆喷 和用户态利用大同小异, 很快学完之后, 陷入了恐慌, 恐慌的原因在于自己清楚的知道, 自己远远不够, 但学习的道路确实断了, 没有方向, 不知道下一步该迈向哪里, 我尝试阅读源码, 但太过晦涩, 放弃, 最后只挑选了内核启动这块做了简单的分析, 但内核入门远远不够

+ 冷静下来之后准备先换个方向继续学习, 于是选择路由器, 折腾一段时间之后, 懂了一个道理, 路由器似乎难点在于环境搭建, 你总是不能搭建一个合适的环境(能让exp顺便跑通, 即使exp异常简单)

+ 陆续的分析了几个路由器cve之后, 发现大多数是命令注入和栈溢出, 很显然从利用的角度来说, 是比较简单的利用

+ 拆了自家的路由器, 不到一个下午就找到了一个明显的栈溢出, 于是利用弹shell一气呵成, 不过, 并没有想象中的高兴(路由器厂商鱼龙混杂, 安全意识参差不齐, 这并不是一件值得开心的事情)

+ 接触fuzz, 阅读afl源码

+ 夏天到了, 疫情有所缓解, 在朋友的推荐下参与了一些安全企业的ctf出题, 以及地方企业的安全培训工作(不管是出题还是安全培训都在一定意义上让我重新回顾了基础知识, 并有所提高)

## 2020(大三)

+ 2020年秋天, 困扰了我两年的问题还是没有得到解决, 另外对于内核的学习已经陷入僵局

+ 下定决心阅读内核源码, 源码读的每天都很煎熬

+ 大概坚持了一个月把, 和很久以前阅读ptmalloc源码一样, 突然开了窍, 一边做笔记, 一边继续阅读源码, 于是写成了: linux内核(5.4.81)---内存管理模块源码分析, 读完源码之后, 我解决了进程间内存空间为什么不相互影响的疑惑, 但是对于进程运行还是存在疑惑(进程如何切换)

+ 为了解决上诉问题, 继续阅读内核进程管理源码, 对于调度策略并不感兴趣, 所以这次大概花了两天时间, 就掌握了我想知道的东西

+ 至此, 我好像真的解决了那个敦促我转专业进入网安的问题, hello_world的运行原理

+ 开新坑进行 linux内核网络模块源码分析, 预期一个月内完成

+ 开始复现内核cve, 期间发现内核cve的难点在于对于内核源码的理解, 恰好, 我对内核源码有一些理解, 所以cve复现速度可喜

+ 开始复现linux 用户态cve, 因为具有pwn经验, 所以用户态cve复现速度也很可观

+ 开始尝试自定义fuzz工具, 尝试挖掘二进制漏洞, 因为前期阅读过fuzz工具源码, 所以这部分思路比较活跃, 等待结果

+ 开始尝试进行代码审计







