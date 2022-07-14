# linux内核(5.4.81)---网络模块源码分析


发表于[安全客](https://www.anquanke.com/post/id/243044)

* [1. socket](#socket)
	* [1.1 sock_create](#sock_create)
	* [1.1.1 sock_alloc](#sock_alloc)
	* [1.1.2 inet_create](#inet_create)
	* [1.1.2.1 sk_alloc](#sk_alloc)
	* [1.2 sock_map_fd](#sock_map_fd)
* [2. send(运输层)](#send)
	* [2.1 import_single_range](#import_single_range)
	* [2.2 sockfd_lookup_light](#sockfd_lookup_light)
	* [2.3 sock_sendmsg](#sock_sendmsg)
	* [2.4 udp_sendmsg](#udp_sendmsg)
	* [2.4.1 udp_cmsg_send](#udp_cmsg_send)
	* [2.4.2 TOS](#TOS)
	* [2.4.3 多播/本地广播](#)
	* [2.4.4 检查sock中路由信息是否过期](#sock)
	* [2.4.5 udp_send_skb](#udp_send_skb)
	* [2.4.6 udp_push_pending_frames](#udp_push_pending_frames)
* [3. recv(运输层)](#recv)
	* [2.1 udp_recvmsg](#udp_recvmsg)
	* [2.1.1 __skb_recv_udp](#skb_recv_udp)
	* [2.1.1.1 __skb_try_recv_from_queue](#skb_try_recv_from_queue)
* [4. IP(网络层)](#IP)
	* [4.1 ip_cmsg_send](#ip_cmsg_send)
	* [4.2 ip_make_skb](#ip_make_skb)
	* [4.2.1 ip_setup_cork](#ip_setup_cork)
	* [4.2.2 __ip_make_skb](#ip_make_skb-1)
	* [4.3 ip_append_data](#ip_append_data)
	* [4.3.1 __ip_append_data](#ip_append_data-1)
	* [4.4 ip_send_skb](#ip_send_skb)
	* [4.4.1 __ip_local_out](#ip_local_out)

## 1. socket

+ SOCK_CLOEXEC 和 SOCK_NONBLOCK是2.6.27版本后增加的sock类型:

    - SOCK_CLOEXEC 借助文件描述符FD_CLOEXEC 实现子进程运行exec后关闭sock_fd机制

    - SOCK_NONBLOCK 借助文件描述符O_NONBLOCK 实现非阻塞IO通信

``` c
int __sys_socket(int family, int type, int protocol)
{
	int retval;
	struct socket *sock;
	int flags;

	/* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

    // 如果flags除SOCK_CLOEXEC/SOCK_NONBLOCK掩码外不存在其他flag标志, 直接返回错误码
	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

    // 因为SOCK_NONBLOCK实现的本质是借助O_NONBLOCK, 所以二者内容矛盾时, 使用O_NONBLOCK替换SOCK_NONBLOCK
	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

    // 创建socket, 详细见1.1
	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		return retval;

    // 将fd, file, socket互相绑定, 详细见1.2
	return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
}
```

### 1.1 sock_create

> sock_create

``` c
int sock_create(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
}
```

> __sock_create

``` c
int __sock_create(struct net *net, int family, int type, int protocol,
			 struct socket **res, int kern)
{
	int err;
	struct socket *sock;
	const struct net_proto_family *pf;

	/*
	 *      Check protocol is in range
	*/
    // 检查协议族是否超出范围
	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;

    // 检查socket类型是否超出范围
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	/* Compatibility.

	   This uglymoron is moved from INET layer to here to avoid
	   deadlock in module load.
	*/
    // SOCK_PACKET被从PF_INET族移入PF_PACKET
	if (family == PF_INET && type == SOCK_PACKET) {
		pr_info_once("%s uses obsolete (PF_INET,SOCK_PACKET)\n",
			     current->comm);
		family = PF_PACKET;
	}

    // 用来适配LSM(linux security module):LSM是一种安全框架，
    // 将钩子安插在内核的关键函数上, 通过钩子上存储函数指针链表调用安全检查函数
    // 用以在不修改内核代码的前提下, 为内核安装安全模块。
    // 理论上讲不同的安全模块可以被同时安装到内核中, 钩子函数会依次执行对应的安全检查函数。
	err = security_socket_create(family, type, protocol, kern);
	if (err)
		return err;

	/*
	 *	Allocate the socket and allow the family to set things up. if
	 *	the protocol is 0, the family is instructed to select an appropriate
	 *	default.
	 */
    // 创建socket, 详细见1.1.1
	sock = sock_alloc();
	if (!sock) {
		net_warn_ratelimited("socket: no more sockets\n");
		return -ENFILE;	/* Not exactly a match, but its the
				   closest posix thing */
	}

    // 为socket->type填充socket类型信息
	sock->type = type;

#ifdef CONFIG_MODULES
	/* Attempt to load a protocol module if the find failed.
	 *
	 * 12/09/1996 Marcin: But! this makes REALLY only sense, if the user
	 * requested real, full-featured networking support upon configuration.
	 * Otherwise module support will break!
	 */
	// 如果协议族内容不存在, 则试图加载驱动(内核执行用户指令modprobe加载驱动)
	if (rcu_access_pointer(net_families[family]) == NULL)
		request_module("net-pf-%d", family);
#endif

	// 进入rcu_read区域, 有关rcu的扩展可以看这篇文章 [RCU简介](https://zhuanlan.zhihu.com/p/113999842)
	rcu_read_lock();
	// 获得协议族信息
	pf = rcu_dereference(net_families[family]);
	err = -EAFNOSUPPORT;
	if (!pf)
		goto out_release;

	/*
	 * We will call the ->create function, that possibly is in a loadable
	 * module, so we have to bump that loadable module refcnt first.
	 */
	// 检查协议族对应的模块是否被加载&增加模块的引用数
	if (!try_module_get(pf->owner))
		goto out_release;

	/* Now protected by module ref count */
	rcu_read_unlock();

	// 在udp中调用inet_create创建sock, 详细见1.1.2
	err = pf->create(net, sock, protocol, kern);
	if (err < 0)
		goto out_module_put;

	/*
	 * Now to bump the refcnt of the [loadable] module that owns this
	 * socket at sock_release time we decrement its refcnt.
	 */

	// 用户需要使用sock->ops, 所以他对应的模块必须在内存中加载
	if (!try_module_get(sock->ops->owner))
		goto out_module_busy;

	/*
	 * Now that we're done with the ->create function, the [loadable]
	 * module can have its refcnt decremented
	 */
	
	// pf->create函数调用完毕, 协议族对应的可加载模板引用数-1
	module_put(pf->owner);
	err = security_socket_post_create(sock, family, type, protocol, kern);
	if (err)
		goto out_sock_release;
	*res = sock;

	return 0;

out_module_busy:
	err = -EAFNOSUPPORT;
out_module_put:
	sock->ops = NULL;
	module_put(pf->owner);
out_sock_release:
	sock_release(sock);
	return err;

out_release:
	rcu_read_unlock();
	goto out_sock_release;
}
```

### 1.1.1 sock_alloc

``` c
struct socket *sock_alloc(void)
{
	struct inode *inode;
	struct socket *sock;

	// 创建inode文件索引结点
	// alloc inode时, 会分配sizeof(struct socket_alloc) 大小空间
	inode = new_inode_pseudo(sock_mnt->mnt_sb);
	if (!inode)
		return NULL;

	// 依据vfs_inode在struct socket_alloc中的偏移定位socket_alloc地址, 然后定位socket 成员位置
	/*
	struct socket_alloc {
		struct socket socket;
		struct inode vfs_inode;
	};
	static inline struct socket *SOCKET_I(struct inode *inode)
	{
		return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
	}
	*/
	sock = SOCKET_I(inode);

	// 填充inode属性, 
	inode->i_ino = get_next_ino();
	inode->i_mode = S_IFSOCK | S_IRWXUGO;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_op = &sockfs_inode_ops;

	return sock;
}
```

### 1.1.2 inet_create

``` c
static int inet_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct sock *sk;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	int try_loading_module = 0;
	int err;

	// 检查协议是否超出范围
	if (protocol < 0 || protocol >= IPPROTO_MAX)
		return -EINVAL;

	// 设置socket为无连接状态
	sock->state = SS_UNCONNECTED;

	/* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	
	// 此宏定义使用了RCU机制, 大致功能为遍历 &inetsw[sock->type] 链表, 
	// 同时返回链表的next指针, 认为该指针是struct inet_protosw中的list成员, 
	// 根据相对偏移, 定位此链表指针对应的结构体首地址, 赋值给answer

	// 遍历对应sock->type的inetsw链表, 查找协议族中与socket类型相对应的网络层协议信息
	// IPPROTO_IP表示用户不指定协议, 使用默认协议
	list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {

		err = 0;
		/* Check the non-wild match. */
		// 如果遍历获得与用户指定协议相同的网络协议(IPPROTO_IP除外), 成功退出
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			// 用户指定IPPROTO_IP后, 使用默认协议
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			// 遍历获得的协议必须非IPPROTO_IP(即必须指定确定协议)
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}

	// 为了解决上诉错误, 此处决定尝试加载驱动(最多尝试两次)
	if (unlikely(err)) {
		if (try_loading_module < 2) {
			rcu_read_unlock();
			/*
			 * Be more specific, e.g. net-pf-2-proto-132-type-1
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP-type-SOCK_STREAM)
			 */
			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d",
					       PF_INET, protocol, sock->type);
			/*
			 * Fall back to generic, e.g. net-pf-2-proto-132
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP)
			 */
			else
				request_module("net-pf-%d-proto-%d",
					       PF_INET, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}

	err = -EPERM;
	// 调用SOCK_RAW, 需要验证权限
	if (sock->type == SOCK_RAW && !kern &&
	    !ns_capable(net->user_ns, CAP_NET_RAW))
		goto out_rcu_unlock;

	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_flags = answer->flags;
	rcu_read_unlock();

	WARN_ON(!answer_prot->slab);

	err = -ENOBUFS;

	// sk_alloc 创建sock(真实大小: sizeof(struct xxx_sock). 比如udp对应udp_sock), 详细见1.1.2.1
	sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot, kern);
	if (!sk)
		goto out;

	err = 0;
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = SK_CAN_REUSE;

	// 将sock转化为inet_sock(包含sock成员)
	inet = inet_sk(sk);
	inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

	inet->nodefrag = 0;
	...

	// 检查配置确定是否开启动态mtu探测
	if (net->ipv4.sysctl_ip_no_pmtu_disc)
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	inet->inet_id = 0;

	// socket与sock相互绑定
	sock_init_data(sock, sk);

	// 初始化sock与inet属性
	sk->sk_destruct	   = inet_sock_destruct;
	sk->sk_protocol	   = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	inet->uc_ttl	= -1;
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;
	inet->rcv_tos	= 0;
	...

out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
}
```

### 1.1.2.1 sk_alloc

``` c
struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot, int kern)
{
	struct sock *sk;

	// 如果协议族存在slab则使用kmem_cache_alloc(slab, priority & ~__GFP_ZERO); 分配内存(不使用内核通用的slab, 可预防内存攻击)
    // 如果协议族slab为空, 使用kmalloc分配内存
	sk = sk_prot_alloc(prot, priority | __GFP_ZERO, family);
	if (sk) {
		// 指定sock协议族
		sk->sk_family = family;
		/*
		 * See comment in struct sock definition to understand
		 * why we need sk_prot_creator -acme
		 */
		sk->sk_prot = sk->sk_prot_creator = prot;
		sk->sk_kern_sock = kern;
		sock_lock_init(sk);
		sk->sk_net_refcnt = kern ? 0 : 1;
		if (likely(sk->sk_net_refcnt)) {
			get_net(net);
			sock_inuse_add(net, 1);
		}

		// 将sock与net相互绑定
		sock_net_set(sk, net);
		refcount_set(&sk->sk_wmem_alloc, 1);
		...
	}

	return sk;
}
```

### 1.2 sock_map_fd

``` c
static int sock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;
	
	// 获得空闲fd
	int fd = get_unused_fd_flags(flags);
	if (unlikely(fd < 0)) {
		// 失败后释放socket
		sock_release(sock);
		return fd;
	}

	// 创建file对象 
	// 调用alloc_file_pseudo, 以socket对应的inode为基础创建file对象,
	// socket文件功能函数替换原生功能函数
	/*
	file与socket相互绑定
	sock->file = file;
	file->private_data = sock;
	*/
	newfile = sock_alloc_file(sock, flags, NULL);
	if (!IS_ERR(newfile)) {

		// fd与file相互绑定
		fd_install(fd, newfile);
		return fd;
	}

	put_unused_fd(fd);
	return PTR_ERR(newfile);
}
```

## 2. send(运输层)

``` c
int __sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags,
		 struct sockaddr __user *addr,  int addr_len)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err;
	struct msghdr msg;
	struct iovec iov;
	int fput_needed;

	// 将待传输数据地址(判断该地址是否为用户态地址)和长度填充进入iov结构体, 
	// 使用uaccess_kernel()判断当前系统调用可访问空间是否为全部空间(KERNEL_DS), 
	// 由此决定使用 msg.msg_iter->kvec/msg.msg_iter->iov保存用户数据信息
	// 详细见2.1
	err = import_single_range(WRITE, buff, len, &iov, &msg.msg_iter);
	if (unlikely(err))
		return err;
	
	// 通过fd获得struct fd, struct fd间接引用file, 然后通过file->private_data获得socket
	// 详细见2.2
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	msg.msg_name = NULL;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;
	if (addr) {
		// 使用copy_from_user将用户空间存储的目标地址复制到内核,
		// 期间会判断目标地址长度是否大于 sizeof(struct sockaddr_storage)
		err = move_addr_to_kernel(addr, addr_len, &address);
		if (err < 0)
			goto out_put;
		msg.msg_name = (struct sockaddr *)&address;
		msg.msg_namelen = addr_len;
	}
	// 设置非阻塞IO
	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	msg.msg_flags = flags;
	err = sock_sendmsg(sock, &msg);

out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}
```

### 2.1 import_single_range

``` c
int import_single_range(int rw, void __user *buf, size_t len,
		 struct iovec *iov, struct iov_iter *i)
{
	if (len > MAX_RW_COUNT)
		len = MAX_RW_COUNT;
    
    // 检查 buf:buf+len 是否指向用户区域
	if (unlikely(!access_ok(buf, len)))
		return -EFAULT;

    // 记录用户数据地址与长度
	iov->iov_base = buf;
	iov->iov_len = len;

    // i->count = count; 将数据长度记录进入msg.msg_iter->count
	iov_iter_init(i, rw, iov, 1, len);
	return 0;
}
```

> iov_iter_init

``` c
void iov_iter_init(struct iov_iter *i, unsigned int direction,
			const struct iovec *iov, unsigned long nr_segs,
			size_t count)
{
	// 不能存在读写之外的标志位
	WARN_ON(direction & ~(READ | WRITE));
	// 忽略传入标志位, 直接赋予READ | WRITE
	direction &= READ | WRITE;

	// uaccess_kernel()判断当前系统调用可访问空间是否为全部空间(KERNEL_DS),
	// 由此决定使用ITER_KVEC / ITER_IOVEC
	// msg.msg_iter->kvec/iov为union类型
	if (uaccess_kernel()) {
		i->type = ITER_KVEC | direction;
		i->kvec = (struct kvec *)iov;
	} else {
		i->type = ITER_IOVEC | direction;
		i->iov = iov;
	}
	i->nr_segs = nr_segs;
	i->iov_offset = 0;
	i->count = count;
}
```

### 2.2 sockfd_lookup_light

``` c
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	// 通过fd获得struct fd
	struct fd f = fdget(fd);
	struct socket *sock;

	*err = -EBADF;
	// 查看struct fd是否与file绑定
	if (f.file) {
		/*	判断file文件操作结构体成员是否与socket文件操作结构体相同, 
			相同则说明struct fd内绑定的确实是socket文件, 
			返回file->private_data即socket
			if (file->f_op == &socket_file_ops)
				return file->private_data;
		*/
		sock = sock_from_file(f.file, err);
		if (likely(sock)) {
			// 表示可解除对该文件描述符的引用
			*fput_needed = f.flags & FDPUT_FPUT;
			return sock;
		}
		fdput(f);
	}
	return NULL;
}
```

### 2.3 sock_sendmsg

> sock_sendmsg -> sock_sendmsg_nosec -> inet_sendmsg -> udp_sendmsg (层层封装)

``` c
int sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
    // LSM hook
	int err = security_socket_sendmsg(sock, msg,
					  msg_data_left(msg));

	return err ?: sock_sendmsg_nosec(sock, msg);
}
```

+ (假设family=AF_INET, protocol=UDP)调用sock->ops->sendmsg, 调用协议族自带的sendmsg功能函数(inet_sendmsg)

``` c
// msg_data_left(msg) 获得用户数据大小(msg.msg_iter->count)

static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
	int ret = INDIRECT_CALL_INET(sock->ops->sendmsg, inet6_sendmsg,
				     inet_sendmsg, sock, msg,
				     msg_data_left(msg));
	BUG_ON(ret == -EIOCBQUEUED);
	return ret;
}
```

+ 根据socket获得sock, 由protocol决定调用功能函数(udp_sendmsg)

``` c
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

    // 如果没有绑定端口, 这里自动绑定端口
	if (unlikely(inet_send_prepare(sk)))
		return -EAGAIN;

	return INDIRECT_CALL_2(sk->sk_prot->sendmsg, tcp_sendmsg, udp_sendmsg,
			       sk, msg, size);
}
```

+ 栈回溯

``` c
gef➤  bt
#0  udp_sendmsg (sk=0xffff888005c7d680, msg=0xffffc900001b7e10, len=0x800) at net/ipv4/udp.c:969
#1  0xffffffff819f4135 in inet_sendmsg (sock=<optimized out>, msg=0xffffc900001b7e10, size=0x800) at net/ipv4/af_inet.c:807
#2  0xffffffff8190ba9e in sock_sendmsg_nosec (msg=<optimized out>, sock=<optimized out>) at ./include/linux/uio.h:235
#3  sock_sendmsg (sock=0xffff888006817a80, msg=0xffffc900001b7e10) at net/socket.c:657
#4  0xffffffff8190de13 in __sys_sendto (fd=<optimized out>, buff=<optimized out>, len=<optimized out>, flags=0x0, addr=0x7ffde0c0cf10, addr_len=0x10) at net/socket.c:1952
```

### 2.4 udp_sendmsg

+ 前置知识

    + 宏定义展开

        -  DECLARE_SOCKADDR

        ``` c
        // struct sockaddr_in * sin= ({__sockaddr_check_size(sizeof(*sin)); (struct sockaddr_in *) msg->msg_name;})
        DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
        ```

        - IS_UDPLITE: 传统的 UDP 通信对整个报文进行校验, UDP-LITE 通信则可以设置校验的长度, 适用于可以接受轻微的报文内容出错的应用场景

        ``` c
        // int err, is_udplite = (sk) (sk->sk_protocol == IPPROTO_UDPLITE)
        int err, is_udplite = IS_UDPLITE(sk);
        ```

+ 根据socket获得inet_sock, udp_sock

``` c
struct inet_sock *inet = inet_sk(sk);
struct udp_sock *up = udp_sk(sk);
```

+ udp_sock的corkflag标志或msg中的MSG_MORE标志存在则开启软木塞机制

``` c
int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
```

+ udp 不能处理带外数据请求

``` c   
if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
    return -EOPNOTSUPP;
```

+ 尝试追加数据(由udp_sock->pending决定), 进入do_append_data, 阻塞追加

``` c
if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			goto do_append_data;
		}
		release_sock(sk);
	}
```

+ ulen 表示udp报文大小(带udphdr)

``` c
ulen += sizeof(struct udphdr);
```

+ usin包含目标ip, 端口, 协议族信息. 在udp协议中, usin应使用AF_INET或AF_UNSPEC(支持同时返回IPv4&IPv6 信息). 同时如果当前状态为TCP_ESTABLISHED, 表示udp连接已经被建立(connected), usin可为空, 接下来需要继承上次通信对应的ip与端口信息. 

``` c 
if (usin) {
	// 如果udp_send 存在目标位置, 则检查协议族, 
    if (msg->msg_namelen < sizeof(*usin))
        return -EINVAL;
    if (usin->sin_family != AF_INET) {
        if (usin->sin_family != AF_UNSPEC)
            return -EAFNOSUPPORT;
    }

	// 填充目标ip与端口信息(端口必须存在)
    daddr = usin->sin_addr.s_addr;
    dport = usin->sin_port;
    if (dport == 0)
        return -EINVAL;
} else {
	// TCP_ESTABLISHED表示udp连接已经被建立, 所以可以不需要目标位置信息
    if (sk->sk_state != TCP_ESTABLISHED)
        return -EDESTADDRREQ;
    daddr = inet->inet_daddr;
    dport = inet->inet_dport;
    /* Open fast path for connected socket.
        Route will not be used, if at least one option is set.
        */
    connected = 1;
}
```

+ 处理udp协议控制信息

``` c 
// ipc用来记录控制信息
ipcm_init_sk(&ipc, inet);

// udp分片长度
ipc.gso_size = up->gso_size;

// 开始解析控制信息, 填充至ipc, 详细见2.4.1
if (msg->msg_controllen) {
	err = udp_cmsg_send(sk, msg, &ipc.gso_size);

	// cmsg->cmsg_level中存在SOL_UDP(need_ip = true), 进入ip_cmsg_send, 详细见4.1
	if (err > 0)
		err = ip_cmsg_send(sk, msg, &ipc,
					sk->sk_family == AF_INET6);
	if (unlikely(err < 0)) {
		kfree(ipc.opt);
		return err;
	}
	if (ipc.opt)
		free = 1;
	connected = 0;
}
```

+ 为ipc.opt 填充ip 选项信息(如果cmsg中存在ip选项信息, 则提前填充, 掠过此处). 即如果用户没有自定义ip 选项信息, 则使用inet默认的ip 选项信息

```
// ip 选项描述结构体
/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @nexthop - Saved nexthop address in LSRR and SSRR
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	__be32		faddr;
	__be32		nexthop;
	unsigned char	optlen;
	unsigned char	srr;
	unsigned char	rr;
	unsigned char	ts;
	unsigned char	is_strictroute:1,
			srr_is_hit:1,
			is_changed:1,
			rr_needaddr:1,
			ts_needtime:1,
			ts_needaddr:1;
	unsigned char	router_alert;
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[0];
}; 
```

``` c
if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		
		inet_opt = rcu_dereference(inet->inet_opt);
		// 将inet->inet_opt->opt拷贝给opt_copy
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			// 填充ipc.opt
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}
```

+ 检查是否设置了源记录路由(source record route, SRR) IP 选项. SRR 有两种类型: 宽松源记录路由/严格源记录路由. 如果设置SRR, 则会记录第一跳地址并保存到faddr, 然后将socket 标记为unconnected

``` c
if (ipc.opt && ipc.opt->opt.srr) {
    if (!daddr) {
        err = -EINVAL;
        goto out_free;
    }
    faddr = ipc.opt->opt.faddr;
    connected = 0;
}
```

+ 获得tos标志(优先从控制信息ipc中获取, 没有自定义则从inet默认获取tos), tos详细见2.4.2

``` c
tos = get_rttos(&ipc, inet);
```

+ 禁止路由设置可以由三种方式控制

``` c
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->opt.is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}
```

+ 选择网卡设备, 多播见2.4.3

``` c
// 通过判断目的地址是否位于224.0.0.0/4 网段, 确定是否为多播
if (ipv4_is_multicast(daddr)) {
	// 设置设备索引为多播设备
    if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
        ipc.oif = inet->mc_index;
    
	// 如果没有设置源地址, 则设置源地址为多播地址
	if (!saddr)
        saddr = inet->mc_addr;
    connected = 0;
} else if (!ipc.oif) {
	// 协议控制信息没有设置设备索引且非多播则设置设备索引为单播设备索引
    ipc.oif = inet->uc_index;
} else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
    /* oif is set, packet is to local broadcast and
        * and uc_index is set. oif is most likely set
        * by sk_bound_dev_if. If uc_index != oif check if the
        * oif is an L3 master and uc_index is an L3 slave.
        * If so, we want to allow the send using the uc_index.
        */
	// 协议控制信息已设置设备索引&消息本地广播&inet存在单播设备&ipc未与inet单播设备绑定
	// 如果ipc绑定inet网卡设备的l3主设备(虚拟网卡), 更改绑定设备为inet网卡(本地广播不需要l3mdev辅助实现VRF)
	// 关于VRF建议阅读: https://blog.csdn.net/dog250/article/details/78069964
    if (ipc.oif != inet->uc_index &&
        ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
                                inet->uc_index)) {
        ipc.oif = inet->uc_index;
    }
}
```

+ 获得路由信息

``` c

if (connected)
		// 如果正在连接, 检查路由是否过期, 详细见2.4.4
		rt = (struct rtable *)sk_dst_check(sk, 0);
if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);

		fl4 = &fl4_stack;

		// flowi4_init_output初始化flow, 描述udp数据流信息
		flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   flow_flags,
				   faddr, saddr, dport, inet->inet_sport,
				   sk->sk_uid);

		// LSM
		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		
		// 获得路由表项
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;

		// 广播路由必须由具有配置SOCK_BROADCAST 标志的sock接收
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			// 如果当前sock 处于connected状态, 则将路由保存至sk->sk_dst_cache
			sk_dst_set(sk, dst_clone(&rt->dst));
	}
```

+ 对于用于探测的数据包, 如果配置了MSG_CONFIRM标志, 则更新邻居结点ARP缓存时间戳, 防止ARP缓存过期

``` c
if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;

...
do_confirm:
	if (msg->msg_flags & MSG_PROBE)
		dst_confirm_neigh(&rt->dst, &fl4->daddr);
```

+ 非阻塞情况下

``` c
if (!corkreq) {
		struct inet_cork cork;

		// 构建 skb, 详细见4.2
		skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
				  sizeof(struct udphdr), &ipc, &rt,
				  &cork, msg->msg_flags);
		err = PTR_ERR(skb);
		if (!IS_ERR_OR_NULL(skb))
			// 传输skb 至网络层, 详细见1.4.5
			err = udp_send_skb(skb, fl4, &cork);
		goto out;
	}
```

+ 阻塞情况下

``` c
	/*
	 *	Now cork the socket to pend data.
	 */
	fl4 = &inet->cork.fl.u.ip4;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->fl4_dport = dport;
	fl4->fl4_sport = inet->inet_sport;
	up->pending = AF_INET;

do_append_data:
	up->len += ulen;
	err = ip_append_data(sk, fl4, getfrag, msg, ulen,
			     sizeof(struct udphdr), &ipc, &rt,
			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		// 链接skb过程中发生错误, 丢弃skb
		udp_flush_pending_frames(sk);
	else if (!corkreq)
		// 组织链接skb后调用udp_send_skb, 填充udp头部并将skb传输给ip层, 详细见2.4.6
		err = udp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		up->pending = 0;
	release_sock(sk);
```

### 2.4.1 udp_cmsg_send

+ 通过相关patch进行分析得出以下结论. [patch1](https://www.spinics.net/lists/netdev/msg496109.html)  [patch2](https://patchwork.ozlabs.org/project/netdev/cover/20180426174225.246388-1-willemdebruijn.kernel@gmail.com/#1901515): 添加GSO机制, 用户可以在一次系统调用中, 向同一目的ip发送多个报文

> udp_cmsg_send

``` c
// 遍历被切割成多个cmsg的msg->control
int udp_cmsg_send(struct sock *sk, struct msghdr *msg, u16 *gso_size)
{
    struct cmsghdr *cmsg;
	bool need_ip = false;
	int err;
	
	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		// 存在非UDP层控制信息, 下一步会进入ip_cmsg_send解析
		if (cmsg->cmsg_level != SOL_UDP) {
			need_ip = true;
			continue;
		}

		err = __udp_cmsg_send(cmsg, gso_size);
		if (err)
			return err;
	}

	return need_ip;
}
``` 

> udp_cmsg_send->for_each_cmsghdr(cmsg, msg)

+ 将msg->control切割成多个cmsg, 具体逻辑:
	
	- 获得第一个cmsg: cmsg = msg->control(msg->controllen >= sizeof(struct cmsghdr)), cmsghdr结构体包含__cmsg_data __flexarr 成员, 该成员为可变字符数组, 用来存储cmsg, 也就是说msg->control中的数据按照cmsghdr结构储存管理, 且cmsghdr结构可变

	- 获得next_cmsg: next_cmsg = cmsg + (align)cmsg->cmsg_len(cmsg+cmsg->cmsg_len+1-msg->control > msg->msg_controllen)

``` c
#define for_each_cmsghdr(cmsg, msg) \
	for (cmsg = CMSG_FIRSTHDR(msg); \
	     cmsg; \
	     cmsg = CMSG_NXTHDR(msg, cmsg))

/* CMSG_FIRSTHDR:
#define CMSG_FIRSTHDR(msg)	__CMSG_FIRSTHDR((msg)->msg_control, (msg)->msg_controllen)

#define __CMSG_FIRSTHDR(ctl,len) ((len) >= sizeof(struct cmsghdr) ? \
				  (struct cmsghdr *)(ctl) : \
				  (struct cmsghdr *)NULL)
*/

/* CMSG_NXTHDR:
#define CMSG_NXTHDR(mhdr, cmsg) cmsg_nxthdr((mhdr), (cmsg))

static inline struct cmsghdr * cmsg_nxthdr (struct msghdr *__msg, struct cmsghdr *__cmsg)
{
	return __cmsg_nxthdr(__msg->msg_control, __msg->msg_controllen, __cmsg);
}

static inline struct cmsghdr * __cmsg_nxthdr(void *__ctl, __kernel_size_t __size,
					       struct cmsghdr *__cmsg)
{
	struct cmsghdr * __ptr;

	__ptr = (struct cmsghdr*)(((unsigned char *) __cmsg) +  CMSG_ALIGN(__cmsg->cmsg_len));
	if ((unsigned long)((char*)(__ptr+1) - (char *) __ctl) > __size)
		return (struct cmsghdr *)0;

	return __ptr;
}
```

> udp_cmsg_send->__udp_cmsg_send

``` c
static int __udp_cmsg_send(struct cmsghdr *cmsg, u16 *gso_size)
{
	switch (cmsg->cmsg_type) {
	case UDP_SEGMENT:
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(__u16)))
			return -EINVAL;
        
        // 指定GSO报文大小, UDP_SEGMENT类型控制信息, 会在cmsg->__cmsg_data前两字节处指定gso_size
		*gso_size = *(__u16 *)CMSG_DATA(cmsg);
		return 0;
	default:
		return -EINVAL;
	}
}
```

### 2.4.2 TOS

> TOS(8bits) 通过填充flag标志位, 用以表示网络设备提供的服务类型(网络设备必须能够支持, 否则没有任何意义).

+ 前3bits: 废弃, 无意义, 默认000

+ 4bits:
    - 1000 -- minimize delay 最小延迟
    - 0100 -- maximize throughput 最大吞吐量
    - 0010 -- maximize reliability 最高可靠性
    - 0001 -- minimize monetary cost 最小费用
    - 0000 -- normal service 一般服务

+ 末尾1bit: 无意义, 保留

### 2.4.3 多播/本地广播

+ 设置多播/本地广播

	+ 多播可以参考这篇文章(多播技术)[https://www.huaweicloud.com/articles/6369165847f916e2f8a8638a480fb1f8.html], 总结概括如下:

		- 多播用来实现一点对多点的传播, 适用于流媒体, 视频会议等场景

		- 多播类似于广播, 使用特殊ip地址作为目的地址(224.0.0.0/4), 多播数据报文会被路由器抄写为多份, 发送至多个目标. 与广播不同的是, 多播只会向存在多播接收请求的子网转发信息.

		- 对于接收者来说, 如果接收者希望接收某一多播信息, 会使用IGMP协议向本地服务器发送请求申请加入某多播组, 本地路由器会将该接收者加入多播组, 并将该组信息共享至相邻路由节点. 

	+ 本地广播此处不再赘述

### 2.4.4 检查sock中路由信息是否过期

> sk_dst_check

``` c
struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie)
{
	struct dst_entry *dst = sk_dst_get(sk);

	if (dst && dst->obsolete && dst->ops->check(dst, cookie) == NULL) {
		sk_dst_reset(sk);
		dst_release(dst);
		return NULL;
	}

	return dst;
}
```

> sk_dst_check->sk_dst_get(获得路由信息)

``` c
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	rcu_read_lock();
	// 从sk->sk_dst_cache去路由信息
	dst = rcu_dereference(sk->sk_dst_cache);

	// 引用数 +1
	if (dst && !atomic_inc_not_zero(&dst->__refcnt))
		dst = NULL;
	rcu_read_unlock();
	return dst;
}
```

> sk_dst_check->dst->ops->check(ipv4下调用ipv4_dst_check, 检查是否过期)

``` c
static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie)
{
	struct rtable *rt = (struct rtable *) dst;

	/* All IPV4 dsts are created with ->obsolete set to the value
	 * DST_OBSOLETE_FORCE_CHK which forces validation calls down
	 * into this function always.
	 *
	 * When a PMTU/redirect information update invalidates a route,
	 * this is indicated by setting obsolete to DST_OBSOLETE_KILL or
	 * DST_OBSOLETE_DEAD.
	 */

	// dst->obsolete 不等于DST_OBSOLETE_FORCE_CHK表示路由信息过期
	if (dst->obsolete != DST_OBSOLETE_FORCE_CHK || rt_is_expired(rt))
		return NULL;
	return dst;
}
```

### 2.4.5 udp_send_skb

``` c
static int udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4,
			struct inet_cork *cork)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct udphdr *uh;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int datalen = len - sizeof(*uh);
	__wsum csum = 0;

	/*
	 * Create a UDP header
	 */

	// 填充udp头
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = fl4->fl4_dport;
	uh->len = htons(len);
	uh->check = 0;

	// 检查是否满足GSO机制, 直接进入硬件校验
	if (cork->gso_size) {
		const int hlen = skb_network_header_len(skb) +
				 sizeof(struct udphdr);

		if (hlen + cork->gso_size > cork->fragsize) {
			kfree_skb(skb);
			return -EINVAL;
		}
		if (skb->len > cork->gso_size * UDP_MAX_SEGMENTS) {
			kfree_skb(skb);
			return -EINVAL;
		}
		if (sk->sk_no_check_tx) {
			kfree_skb(skb);
			return -EINVAL;
		}
		if (skb->ip_summed != CHECKSUM_PARTIAL || is_udplite ||
		    dst_xfrm(skb_dst(skb))) {
			kfree_skb(skb);
			return -EIO;
		}

		if (datalen > cork->gso_size) {
			skb_shinfo(skb)->gso_size = cork->gso_size;
			skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
			skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(datalen,
								 cork->gso_size);
		}
		goto csum_partial;
	}

	// 进入UDP-LITE 校验和计算, 可通过指定校验长度容忍报文出错现象
	if (is_udplite)  				 /*     UDP-Lite      */
		csum = udplite_csum(skb);

	// 不进行校验
	else if (sk->sk_no_check_tx) {			 /* UDP csum off */

		// CHECKSUM_NONE指不需要校验
		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
csum_partial:
		// CHECKSUM_PARTIAL表示硬件实现部分校验和计算(udp数据校验)
		udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
		goto send;

	} else
		// 软件实现校验和计算(udp数据校验)
		csum = udp_csum(skb);

	/* add protocol-dependent pseudo-header */

	// 设置伪ip头, 计算udp报文校验和与伪ip头的校验和
	uh->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
				      sk->sk_protocol, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	// 将skb传递至网络层(IP层), 详细见4.4
	err = ip_send_skb(sock_net(sk), skb);
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) {
			UDP_INC_STATS(sock_net(sk),
				      UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_OUTDATAGRAMS, is_udplite);
	return err;
}
```

### 2.4.6 udp_push_pending_frames

``` c
int udp_push_pending_frames(struct sock *sk)
{
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	struct sk_buff *skb;
	int err = 0;

	skb = ip_finish_skb(sk, fl4);
	if (!skb)
		goto out;

	err = udp_send_skb(skb, fl4, &inet->cork.base);

out:
	up->len = 0;
	up->pending = 0;
	return err;
}
```

## 3. recv(运输层)

> 大多数api在send中已经提及, 不再次讲解

> __sys_recvfrom -> sock_recvmsg -> sock_recvmsg_nosec -> inet_recvmsg -> udp_recvmsg (层层封装)

``` c
int __sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
		   struct sockaddr __user *addr, int __user *addr_len)
{
	...
	err = sock_recvmsg(sock, &msg, flags);

	if (err >= 0 && addr != NULL) {
		
		// 将客户端地址返回给用户态
		err2 = move_addr_to_user(&address,
					 msg.msg_namelen, addr, addr_len);
		if (err2 < 0)
			err = err2;
	}

	...
```

### 2.1 udp_recvmsg

``` c 
int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int off, err, peeking = flags & MSG_PEEK;
	int is_udplite = IS_UDPLITE(sk);
	bool checksum_valid = false;

	// 从socket错误队列接收错误信息
	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len, addr_len);

try_again:
	// MSG_PEEK表示预读, 此处获得预读长度
	off = sk_peek_offset(sk, flags);

	// 从缓存队列中获得skb, 详细见2.1.1
	skb = __skb_recv_udp(sk, flags, noblock, &off, &err);
	if (!skb)
		return err;

	// 获得skb内数据长度
	ulen = udp_skb_len(skb);
	copied = len;

	// 如果待接收数据大于skb缓存数据, 截断输入
	if (copied > ulen - off)
		copied = ulen - off;
	else if (copied < ulen)
		// 接收skb中所有数据
		msg->msg_flags |= MSG_TRUNC;

	/*
	 * If checksum is needed at all, try to do it while copying the
	 * data.  If the data is truncated, or if we only want a partial
	 * coverage checksum (UDP-Lite), do it before the copy.
	 */
	// CHECKSUM_UNNECESSARY表示硬件已完成数据校验, 无需再次校验
	// 待接收数据小于缓冲区数据&开启预读机制&开启udplite机制情况下如果skb需要进行校验则调用__udp_lib_checksum_complete进行校验
	if (copied < ulen || peeking ||
	    (is_udplite && UDP_SKB_CB(skb)->partial_cov)) {
		checksum_valid = udp_skb_csum_unnecessary(skb) ||
				!__udp_lib_checksum_complete(skb);
		// 校验未通过丢弃数据
		if (!checksum_valid)
			goto csum_copy_err;
	}

	// 如果校验成功或未开启校验则直接复制数据
	if (checksum_valid || udp_skb_csum_unnecessary(skb)) {
		// 如果skb中数据都存在线性区域直接调用copy_linear_skb, 否则使用skb_copy_datagram_msg
		if (udp_skb_is_linear(skb))
			err = copy_linear_skb(skb, copied, off, &msg->msg_iter);
		else
			err = skb_copy_datagram_msg(skb, off, msg, copied);
	} 

	// 此处代码对全部数据做校验
	else {
		// 在复制数据时做完整性校验
		err = skb_copy_and_csum_datagram_msg(skb, off, msg);

		if (err == -EINVAL)
			goto csum_copy_err;
	}

	// 发生错误释放skb, 直接返回
	if (unlikely(err)) {
		if (!peeking) {
			atomic_inc(&sk->sk_drops);
			UDP_INC_STATS(sock_net(sk),
				      UDP_MIB_INERRORS, is_udplite);
		}
		kfree_skb(skb);
		return err;
	}

	if (!peeking)
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_INDATAGRAMS, is_udplite);

	sock_recv_ts_and_drops(msg, sk, skb);

	// 根据skb填充客户端数据
	/* Copy the address. */
	if (sin) {
		sin->sin_family = AF_INET;
		sin->sin_port = udp_hdr(skb)->source;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
		*addr_len = sizeof(*sin);

		// 涉及bpf
		if (cgroup_bpf_enabled)
			BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk,
							(struct sockaddr *)sin);
	}

	// 解析控制信息
	if (udp_sk(sk)->gro_enabled)
		udp_cmsg_recv(msg, sk, skb);

	if (inet->cmsg_flags)
		ip_cmsg_recv_offset(msg, sk, skb, sizeof(struct udphdr), off);

	err = copied;
	if (flags & MSG_TRUNC)
		// 如果开启MSG_TRUNC, 会接收skb中全部数据（在用户缓冲区最大处截断）
		err = ulen;

	skb_consume_udp(sk, skb, peeking ? -err : err);
	return err;

csum_copy_err:
	if (!__sk_queue_drop_skb(sk, &udp_sk(sk)->reader_queue, skb, flags,
				 udp_skb_destructor)) {
		UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
		UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	}
	kfree_skb(skb);

	/* starting over for a new packet, but check if we need to yield */
	cond_resched();
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}
```

### 2.1.1 __skb_recv_udp

``` c
struct sk_buff *__skb_recv_udp(struct sock *sk, unsigned int flags,
			       int noblock, int *off, int *err)
{
	struct sk_buff_head *sk_queue = &sk->sk_receive_queue;
	struct sk_buff_head *queue;
	struct sk_buff *last;
	long timeo;
	int error;

	// 获得缓存队列
	queue = &udp_sk(sk)->reader_queue;

	// 确定是否为非阻塞IO
	flags |= noblock ? MSG_DONTWAIT : 0;

	// 返回阻塞IO时间戳
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	do {
		struct sk_buff *skb;

		// 清空错误报告
		error = sock_error(sk);
		if (error)
			break;

		error = -EAGAIN;
		do {
			// 禁止CPU软中断
			spin_lock_bh(&queue->lock);

			// 尝试获得skb, 详细见2.1.1.1
			skb = __skb_try_recv_from_queue(sk, queue, flags,
							udp_skb_destructor,
							off, err, &last);
			if (skb) {
				// 获得skb后开启软中断
				spin_unlock_bh(&queue->lock);
				return skb;
			}

			// 获取skb失败后, 无锁判断sock接收队列是否为空
			if (skb_queue_empty_lockless(sk_queue)) {
				spin_unlock_bh(&queue->lock);
				goto busy_check;
			}

			/* refill the reader queue and walk it again
			 * keep both queues locked to avoid re-acquiring
			 * the sk_receive_queue lock if fwd memory scheduling
			 * is needed.
			 */
			spin_lock(&sk_queue->lock);

			// 链接sk_queue进入queue
			skb_queue_splice_tail_init(sk_queue, queue);

			// 再次尝试获取skb
			skb = __skb_try_recv_from_queue(sk, queue, flags,
							udp_skb_dtor_locked,
							off, err, &last);
			spin_unlock(&sk_queue->lock);
			spin_unlock_bh(&queue->lock);
			if (skb)
				return skb;

busy_check:
			if (!sk_can_busy_loop(sk))
				break;

			sk_busy_loop(sk, flags & MSG_DONTWAIT);
		} while (!skb_queue_empty_lockless(sk_queue));
		// 直到sk_queue为空, 跳出循环

		/* sk_queue is empty, reader_queue may contain peeked packets */
	} while (timeo &&
		 !__skb_wait_for_more_packets(sk, &error, &timeo,
					      (struct sk_buff *)sk_queue));
	// 如果sock接收队列sk_queue为空, 且需要等待, 在此处等待

	*err = error;
	return NULL;
}
```

### 2.1.1.1 __skb_try_recv_from_queue

``` c
struct sk_buff *__skb_try_recv_from_queue(struct sock *sk,
					  struct sk_buff_head *queue,
					  unsigned int flags,
					  void (*destructor)(struct sock *sk,
							   struct sk_buff *skb),
					  int *off, int *err,
					  struct sk_buff **last)
{
	bool peek_at_off = false;
	struct sk_buff *skb;
	int _off = 0;

	if (unlikely(flags & MSG_PEEK && *off >= 0)) {
		peek_at_off = true;
		_off = *off;
	}

	*last = queue->prev;

	// 遍历队列
	skb_queue_walk(queue, skb) {
		if (flags & MSG_PEEK) {
			// 如果预读的字节数大于skb数据长度, 则更新待预读字节数且更换skb
			if (peek_at_off && _off >= skb->len &&
			    (_off || skb->peeked)) {
				_off -= skb->len;
				continue;
			}

			// skb非空, 设置为预读模式
			if (!skb->len) {
				skb = skb_set_peeked(skb);
				if (IS_ERR(skb)) {
					*err = PTR_ERR(skb);
					return NULL;
				}
			}
			refcount_inc(&skb->users);
		} else {
			// 将skb从队列中取出
			__skb_unlink(skb, queue);

			// 如果定义了销毁函数则调用
			if (destructor)
				destructor(sk, skb);
		}
		*off = _off;
		return skb;
	}
	return NULL;
}
```

## 4. IP(网络层)

### 4.1 ip_cmsg_send

+ 将cmsg中的控制信息, 保存至ipc(可以根据控制信息, 自定义socket和ip层面配置)

``` c
int ip_cmsg_send(struct sock *sk, struct msghdr *msg, struct ipcm_cookie *ipc,
		 bool allow_ipv6)
{
	int err, val;
	struct cmsghdr *cmsg;
	struct net *net = sock_net(sk);

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level == SOL_SOCKET) {
            // 修改socket层面的配置
			err = __sock_cmsg_send(sk, msg, cmsg, &ipc->sockc);
			if (err)
				return err;
			continue;
		}

		if (cmsg->cmsg_level != SOL_IP)
			continue;
		switch (cmsg->cmsg_type) {
		case IP_RETOPTS:
        // 获得ip选项
			err = cmsg->cmsg_len - sizeof(struct cmsghdr);

			/* Our caller is responsible for freeing ipc->opt */
			err = ip_options_get(net, &ipc->opt, CMSG_DATA(cmsg),
					     err < 40 ? err : 40);
			if (err)
				return err;
			break;
		case IP_PKTINFO:
		// 通过控制信息修改源ip
        {
			struct in_pktinfo *info;
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct in_pktinfo)))
				return -EINVAL;
			info = (struct in_pktinfo *)CMSG_DATA(cmsg);
			if (info->ipi_ifindex)
				ipc->oif = info->ipi_ifindex;
			ipc->addr = info->ipi_spec_dst.s_addr;
			break;
		}
		case IP_TTL:
        // 自定义TTL
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)))
				return -EINVAL;
			val = *(int *)CMSG_DATA(cmsg);
			if (val < 1 || val > 255)
				return -EINVAL;
			ipc->ttl = val;
			break;
		case IP_TOS:
        // 自定义TOS
			if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)))
				val = *(int *)CMSG_DATA(cmsg);
			else if (cmsg->cmsg_len == CMSG_LEN(sizeof(u8)))
				val = *(u8 *)CMSG_DATA(cmsg);
			else
				return -EINVAL;
			if (val < 0 || val > 255)
				return -EINVAL;
			ipc->tos = val;
			ipc->priority = rt_tos2priority(ipc->tos);
			break;

		default:
			return -EINVAL;
		}
	}
	return 0;
}
```

### 4.2 ip_make_skb

``` c
truct sk_buff *ip_make_skb(struct sock *sk,
			    struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags)
{
	/*
	struct sk_buff_head {
		/* These two members must be first. */
		struct sk_buff	*next;
		struct sk_buff	*prev;

		__u32		qlen;
		spinlock_t	lock;
	};	
	*/
	struct sk_buff_head queue;
	int err;

	// 路径探测数据包不传输数据, 直接返回
	if (flags & MSG_PROBE)
		return NULL;

	// 创建空闲队列
	__skb_queue_head_init(&queue);

	// 伪造cork
	cork->flags = 0;
	cork->addr = 0;
	cork->opt = NULL;
	
	// 初始化cork, 见4.2.1
	err = ip_setup_cork(sk, cork, ipc, rtp);
	if (err)
		return ERR_PTR(err);

	// 使用队列保存skb, skb组织待传输数据, 详细见4.3.1
	err = __ip_append_data(sk, fl4, &queue, cork,
			       &current->task_frag, getfrag,
			       from, length, transhdrlen, flags);
	if (err) {
		__ip_flush_pending_frames(sk, &queue, cork);
		return ERR_PTR(err);
	}

	// 取出队列中的skb, 设置ip选项, 并链接, 返回一个skb, 详细见4.2.2
	return __ip_make_skb(sk, fl4, &queue, cork);
}
```

### 4.2.1 ip_setup_cork

``` c
static int ip_setup_cork(struct sock *sk, struct inet_cork *cork,
			 struct ipcm_cookie *ipc, struct rtable **rtp)
{
	struct ip_options_rcu *opt;
	struct rtable *rt;

	rt = *rtp;
	if (unlikely(!rt))
		return -EFAULT;

	/*
	 * setup for corking.
	 */
	opt = ipc->opt;
	if (opt) {
		if (!cork->opt) {
			// 为cork->opt分配空间, 最大容纳sizeof(struct ip_options) + 40 bytes
			cork->opt = kmalloc(sizeof(struct ip_options) + 40,
					    sk->sk_allocation);
			if (unlikely(!cork->opt))
				return -ENOBUFS;
		}

		// 缓存opt至cork->opt
		memcpy(cork->opt, &opt->opt, sizeof(struct ip_options) + opt->opt.optlen);
		cork->flags |= IPCORK_OPT;
		cork->addr = ipc->addr;
	}

	// 设置报文分段长度, 开启pmtu探测时调用dst->ops->mtu(dst)获得mtu, 否则从网络设备获得mtu
	cork->fragsize = ip_sk_use_pmtu(sk) ?
			 dst_mtu(&rt->dst) : READ_ONCE(rt->dst.dev->mtu);

	// mtu >= IPV4_MIN_MTU
	if (!inetdev_valid_mtu(cork->fragsize))
		return -ENETUNREACH;

	cork->gso_size = ipc->gso_size;

	// 设置路由
	cork->dst = &rt->dst;
	/* We stole this route, caller should not release it. */
	*rtp = NULL;

	// 基础配置, cork最终会拿到所有ip配置
	// cork->length表示skb已包含数据
	cork->length = 0;
	cork->ttl = ipc->ttl;
	cork->tos = ipc->tos;
	cork->mark = ipc->sockc.mark;
	cork->priority = ipc->priority;
	cork->transmit_time = ipc->sockc.transmit_time;
	cork->tx_flags = 0;
	sock_tx_timestamp(sk, ipc->sockc.tsflags, &cork->tx_flags);

	return 0;
}
```

### 4.2.2 __ip_make_skb

``` c
struct sk_buff *__ip_make_skb(struct sock *sk,
			      struct flowi4 *fl4,
			      struct sk_buff_head *queue,
			      struct inet_cork *cork)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = (struct rtable *)cork->dst;
	struct iphdr *iph;
	__be16 df = 0;
	__u8 ttl;

	// 取出第一个skb
	skb = __skb_dequeue(queue);
	if (!skb)
		goto out;

	// 定位skb非线性区域
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	// 更新skb->data指向ip头
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));

	// 依次取出skb, 使用skb_shinfo(skb)->frag_list作为指针将所有skb链接起来, 同时由链表头skb统计数据长度信息
	while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
		__skb_pull(tmp_skb, skb_network_header_len(skb));
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	// 设置是否开启动态mtu探测
	skb->ignore_df = ip_sk_ignore_df(sk);

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If ignore_df is set too, we still allow to fragment this frame
	 * locally. */
	if (inet->pmtudisc == IP_PMTUDISC_DO ||
	    inet->pmtudisc == IP_PMTUDISC_PROBE ||
	    (skb->len <= dst_mtu(&rt->dst) &&
	     ip_dont_fragment(sk, &rt->dst)))
		df = htons(IP_DF);

	if (cork->flags & IPCORK_OPT)
		opt = cork->opt;

	if (cork->ttl != 0)
		ttl = cork->ttl;
	else if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->dst);

	// 填充skb线性区域的ip头信息
	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = (cork->tos != -1) ? cork->tos : inet->tos;
	iph->frag_off = df;
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);
	ip_select_ident(net, skb, sk);

	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, cork->addr, rt, 0);
	}

	skb->priority = (cork->tos != -1) ? cork->priority: sk->sk_priority;
	skb->mark = cork->mark;
	skb->tstamp = cork->transmit_time;
	/*
	 * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
	 * on dst refcount
	 */
	cork->dst = NULL;
	skb_dst_set(skb, &rt->dst);

	if (iph->protocol == IPPROTO_ICMP)
		icmp_out_count(net, ((struct icmphdr *)
			skb_transport_header(skb))->type);

	ip_cork_release(cork);
out:
	return skb;
}
```

### 4.3 ip_append_data

``` c
int ip_append_data(struct sock *sk, struct flowi4 *fl4,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable **rtp,
		   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	int err;

	// 忽略探测包
	if (flags&MSG_PROBE)
		return 0;

	// 队列为空时, 初始化cork
	if (skb_queue_empty(&sk->sk_write_queue)) {
		err = ip_setup_cork(sk, &inet->cork.base, ipc, rtp);
		if (err)
			return err;
	} else {
		transhdrlen = 0;
	}

	return __ip_append_data(sk, fl4, &sk->sk_write_queue, &inet->cork.base,
				sk_page_frag(sk), getfrag,
				from, length, transhdrlen, flags);
}
```

### 4.3.1 __ip_append_data

``` c
static int __ip_append_data(struct sock *sk,
			    struct flowi4 *fl4,
			    struct sk_buff_head *queue,
			    struct inet_cork *cork,
			    struct page_frag *pfrag,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ubuf_info *uarg = NULL;
	struct sk_buff *skb;

	struct ip_options *opt = cork->opt;
	int hh_len;
	int exthdrlen;
	int mtu;
	int copy;
	int err;
	int offset = 0;
	unsigned int maxfraglen, fragheaderlen, maxnonfragsize;
	int csummode = CHECKSUM_NONE;
	struct rtable *rt = (struct rtable *)cork->dst;
	unsigned int wmem_alloc_delta = 0;
	bool paged, extra_uref = false;
	u32 tskey = 0;

	// 取出队列尾部的skb(这个skb有可能存在部分空闲缓冲区, 可以继续保存数据)
	skb = skb_peek_tail(queue);

	// skb为空(第一个skb), rt->dst.header_len为拓展头长度
	exthdrlen = !skb ? rt->dst.header_len : 0;

	// 如果开启GSO机制, mtu可直接取最大值, 否则取最大报文分段长度
	mtu = cork->gso_size ? IP_MAX_MTU : cork->fragsize;
	paged = !!cork->gso_size;

	if (cork->tx_flags & SKBTX_ANY_SW_TSTAMP &&
	    sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
		tskey = sk->sk_tskey++;

	// 为L2层保留首部长度
	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	// udp头部 + ip选项
	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);

	// payload部分需要8字节对齐
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	// 检查是否设置DF标志(动态mtu探测), 没有开启mtu探测可直接传输最大0xffff字节数据
	maxnonfragsize = ip_sk_ignore_df(sk) ? 0xFFFF : mtu;

	// 如果传输数据超过maxnonfragsize, 则报错退出
	if (cork->length + length > maxnonfragsize - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
			       mtu - (opt ? opt->optlen : 0));
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	// 发送第一个报文&报文长度小于mtu&存在硬件校验(支持全部包校验or校验ipv4协议中的tcp/udp)&非阻塞IO or开启GSO&没有拓展头部or支持ESP硬件分片, 开启硬件校验
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->dst.dev->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM) &&
	    (!(flags & MSG_MORE) || cork->gso_size) &&
	    (!exthdrlen || (rt->dst.dev->features & NETIF_F_HW_ESP_TX_CSUM)))
		csummode = CHECKSUM_PARTIAL;

	// 零拷贝机制, 可以提升大块数据收发速度
	if (flags & MSG_ZEROCOPY && length && sock_flag(sk, SOCK_ZEROCOPY)) {
		uarg = sock_zerocopy_realloc(sk, length, skb_zcopy(skb));
		if (!uarg)
			return -ENOBUFS;
		extra_uref = !skb_zcopy(skb);	/* only ref on new uarg */
		if (rt->dst.dev->features & NETIF_F_SG &&
		    csummode == CHECKSUM_PARTIAL) {
			paged = true;
		} else {
			uarg->zerocopy = 0;
			skb_zcopy_set(skb, uarg, &extra_uref);
		}
	}

	// 更新cork->length长度, 对于阻塞通信, cork->length会表示所有已存储数据长度
	cork->length += length;

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

	// skb为空则新建skb
	if (!skb)
		goto alloc_new_skb;

	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
		// skb->len表示当前skb已存储数据, copy表示本次循环待处理数据长度
		copy = mtu - skb->len;
		// 当前skb不能容纳剩余的所有数据
		if (copy < length)
			copy = maxfraglen - skb->len;

		// 当前skb已满, 需要分配新的skb
		if (copy <= 0) {
			char *data;
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen;
			unsigned int pagedlen;
			struct sk_buff *skb_prev;
alloc_new_skb:
			skb_prev = skb;

			// 如果上一个skb存在, 则说明上一个块已经被填满(skb_prev->len与maxfraglen差值在[0:8)内)
			// 否则说明当前skb为第一个skb, 无需考虑上一个skb剩余数据
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			// datalen记录当前skb需要存储的数据大小, 如果数据超出mtu, 按照最大mtu计算(第一个报文片段需要考虑报文头长度)
			datalen = length + fraggap;
			if (datalen > mtu - fragheaderlen)
				datalen = maxfraglen - fragheaderlen;
			fraglen = datalen + fragheaderlen;
			pagedlen = 0;

			// 如果接下来会有数据传入且硬件不支持分散/聚合IO, 则直接分配mtu大小空间, 否则按需分析
			if ((flags & MSG_MORE) &&
			    !(rt->dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else if (!paged)
				alloclen = fraglen;
			else {
				alloclen = min_t(int, fraglen, MAX_HEADER);
				pagedlen = fraglen - alloclen;
			}

			// 添加拓展头空间
			alloclen += exthdrlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */
			if (datalen == length + fraggap)
				alloclen += rt->dst.trailer_len;

			// 第一次发送报文片段需要考虑运输层(udp)头部, 与其他片段存在差异, 使用sock_alloc_send_skb分配空间
			if (transhdrlen) {
				skb = sock_alloc_send_skb(sk,
						alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} else {
				skb = NULL;
				// 如果当前套接字已分配的写缓冲区总长 > 2*sk->sk_sndbuf则发生错误
				if (refcount_read(&sk->sk_wmem_alloc) + wmem_alloc_delta <=
				    2 * sk->sk_sndbuf)
					// alloc_skb 为skb分配空间
					skb = alloc_skb(alloclen + hh_len + 15,
							sk->sk_allocation);
				if (unlikely(!skb))
					err = -ENOBUFS;
			}
			if (!skb)
				goto error;

			/*
			 *	Fill in the control structures
			 */
			// 选择校验方式
			skb->ip_summed = csummode;

			// 伪造一个校验和, 防止后面计算校验和时出现套娃
			skb->csum = 0;

			// 在skb线性区域为L2保留空间
			// skb->data&skb->head向下移动
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			
			// skb->tail增加, 开辟线性写入空间(skb->head: skb->tail)
			data = skb_put(skb, fraglen + exthdrlen - pagedlen);

			// 设置网络层头
			skb_set_network_header(skb, exthdrlen);

			// 设置传输层头
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			data += fragheaderlen + exthdrlen;

			if (fraggap) {
				// 将pre_skb末尾字节复制到skb, 拷贝时校验
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			// 调用getfrag(), 复制copy字节数据至skb, getfrag由上层协议指定(本例为udp)
			copy = datalen - transhdrlen - fraggap - pagedlen;
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			// 更新偏移
			offset += copy;

			// 递减length(待传输字节数)
			length -= copy + transhdrlen;
			transhdrlen = 0;
			exthdrlen = 0;
			csummode = CHECKSUM_NONE;

			/* only the initial fragment is time stamped */
			// 设置时间戳
			skb_shinfo(skb)->tx_flags = cork->tx_flags;
			cork->tx_flags = 0;
			skb_shinfo(skb)->tskey = tskey;
			tskey = 0;
			skb_zcopy_set(skb, uarg, &extra_uref);

			if ((flags & MSG_CONFIRM) && !skb_prev)
				skb_set_dst_pending_confirm(skb, 1);

			/*
			 * Put the packet on the pending queue.
			 */
			if (!skb->destructor) {
				// 销毁skb后, 恢复相应的wmem_alloc_delta数据容量
				skb->destructor = sock_wfree;
				skb->sk = sk;
				wmem_alloc_delta += skb->truesize;
			}
			// 添加skb至队列
			__skb_queue_tail(queue, skb);
			continue;
		}

		// skb剩余空间足够存储剩余数据
		if (copy > length)
			copy = length;

		// 如果硬件不支持分散/聚合IO, 使用线性区域存储数据
		if (!(rt->dst.dev->features&NETIF_F_SG) &&
		    skb_tailroom(skb) >= copy) {
			unsigned int off;

			off = skb->len;
			
			// 硬件不支持分散/聚合IO, 使用getfrag复制数据至线性区域(更新skb->tail), 更新偏移
			if (getfrag(from, skb_put(skb, copy),
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else if (!uarg || !uarg->zerocopy) {
			// 填充至非线性区域, skb的frags数组中
			int i = skb_shinfo(skb)->nr_frags;

			err = -ENOMEM;
			if (!sk_page_frag_refill(sk, pfrag))
				goto error;

			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				err = -EMSGSIZE;
				if (i == MAX_SKB_FRAGS)
					goto error;

				__skb_fill_page_desc(skb, i, pfrag->page,
						     pfrag->offset, 0);
				skb_shinfo(skb)->nr_frags = ++i;
				get_page(pfrag->page);
			}
			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			if (getfrag(from,
				    page_address(pfrag->page) + pfrag->offset,
				    offset, copy, skb->len, skb) < 0)
				goto error_efault;

			pfrag->offset += copy;
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			wmem_alloc_delta += copy;
		} else {
			// 使用零拷贝技术填充skb
			err = skb_zerocopy_iter_dgram(skb, from, copy);
			if (err < 0)
				goto error;
		}
		// 更新偏移与长度
		offset += copy;
		length -= copy;
	}

	if (wmem_alloc_delta)
		refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
	return 0;

error_efault:
	err = -EFAULT;
error:
	if (uarg)
		sock_zerocopy_put_abort(uarg, extra_uref);
	cork->length -= length;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
	return err;
}
```

### 4.4 ip_send_skb

> ip_send_skb->ip_local_out

``` c
int ip_send_skb(struct net *net, struct sk_buff *skb)
{
	int err;

	err = ip_local_out(net, skb->sk, skb);
	if (err) {
		if (err > 0)
			// 传递底层错误信息至上层协议
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	return err;
}
```

``` c
int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int err;

	// 填充ip头部, 判断数据包是否允许通过
	err = __ip_local_out(net, sk, skb);
	if (likely(err == 1))
		// 发送数据包
		err = dst_output(net, sk, skb);

	return err;
}
```

### 4.4.1 __ip_local_out

``` c
int __ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	// 填充ip报文长度
	iph->tot_len = htons(skb->len);

	// 计算ip校验和
	ip_send_check(iph);

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	// 设置出口设备为l3主设备(虚拟网卡)
	skb = l3mdev_ip_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	skb->protocol = htons(ETH_P_IP);

	// 检查此处是否存在网络数据包过滤器, 如果存在则执行过滤操作, 并将dst_output作为回调函数
	return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}
```

