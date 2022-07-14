# nginx-ldap-auth之user注入漏洞


> 前段时间, 有人声称发现nginx 0day, 并在[NginxDay](https://github.com/AgainstTheWest/NginxDay)中持续跟进漏洞上报流程, 虽然漏洞确实存在, 但漏洞只存在于一个示例项目, 且漏洞危害较低. 就目前笔者漏洞分析来看, 该行为多少有点花里胡哨, 下面分析一下这个有些鸡肋的漏洞.

+ nginx提供ngx_http_auth_request_module模块用于鉴权, 其功能特点为需要用户自定义实现鉴权api, 并由ngx_http_auth_request_module模块调用

+ nginx-ldap-auth结合ldap实现鉴权机制, 是一种用户自定义实现鉴权api的示例项目

### nginx-ldap-auth功能原理

+ nginx-ldap-auth关键文件

    - backend-sample-app.py(处理登录表单), 将user:passwd base64编码后设置Cookie
    - nginx-ldap-auth-daemon.py(结合ldap进行鉴权), 解析http报文中的Cookie/Authorization(有Cookie的情况下鉴权以Cookie为主)

+ ngx_http_auth_request_module模块常用路由

    1. nginx直接向nginx-ldap-auth-daemon.py对应url发起请求, 此时未设置Cookie/Authorization返回401

    2. nginx转发请求至backend-sample-app.py对应url处理登录表单, 并设置Cookie

    3. nginx重定向请求至nginx-ldap-auth-daemon.py对应url, 此时存在Cookie, 解析user, passwd, 调用ldap实现鉴权, 成功则返回200

### nginx-ldap-auth-daemon.py鉴权分析

从下面鉴权代码可以看出, nginx-ldap-auth-daemon.py使用searchfilter过滤ldap结果, 查找目标登录用户

``` py
// ctx['template']默认对应: 'template': ('X-Ldap-Template', '(cn=%(username)s)'),
// ctx['user'], ctx['pass']: 从Cookie中解析出的user, passwd

searchfilter = ctx['template'] % { 'username': ctx['user'] }
...

// 默认使用(cn=username)这种模式在ldap中查找用户
results = ldap_obj.search_s(ctx['basedn'], ldap.SCOPE_SUBTREE,
                                          searchfilter, ['objectclass'], 1)
user_entry = results[0]
ldap_dn = user_entry[0]
ldap_obj.bind_s(ldap_dn, ctx['pass'], ldap.AUTH_SIMPLE)
```

### 漏洞点

+ ctx['user'] 没有过滤字符, 直接使用http报文提供的数据

``` py
auth_header = self.headers.get('Authorization')
auth_cookie = self.get_cookie(ctx['cookiename'])

if auth_cookie != None and auth_cookie != '':
    auth_header = "Basic " + auth_cookie
...

auth_decoded = base64.b64decode(auth_header[6:])
...

user, passwd = auth_decoded.split(':', 1)
...

// 漏洞点
ctx['user'] = user
ctx['pass'] = passwd
```

+ ctx['template'] 可以被管理员自定义设置, issue提供了一种情况如下:

    - X-Ldap-Template: (|(&(memberOf=x)(cn=%(username)s))(&(memberOf=y)(cn=%(username)s)))

    - 解释上诉规则: |代表或, &代表与, ()括号内容代表|/&的作用区域, 那么上诉规则就可以解析为查找在x组内的username或y组内的username

    - searchfilter = ctx['template'] % { 'username': ctx['user'] }, 见nginx-ldap-auth-daemon.py鉴权分析

+ 结合ctx['template'], ctx['user']的特点, 就可以实现ctx['user']注入

``` py
>>> template="(|(&(memberOf=x)(cn=%(username)s))(&(memberOf=y)(cn=%(username)s)))"
>>> template%{"username": "hack"}
'(|(&(memberOf=x)(cn=hack))(&(memberOf=y)(cn=hack)))'

// 如果ctx['user']="x))((cn=hack", 那么过滤规则就变成查找在x组内的x或hack或y组内的hack
>>> template%{"username": "x))((cn=hack"}
'(|(&(memberOf=x)(cn=x))((cn=hack))(&(memberOf=y)(cn=x))((cn=hack)))'
```

### 漏洞效果

目前来看只能通过user注入, 消除一些认证条件(比如特定组), 比较鸡肋. 当然不排除ldap由其他trick, 本二进制狗不知道=.=

### 补丁分析

``` diff
@@ -88,9 +96,9 @@ def do_GET(self):
...
ctx['pass'] = passwd

// 过滤user字符
+ ctx['user'] = ldap.filter.escape_filter_chars(user)
```


