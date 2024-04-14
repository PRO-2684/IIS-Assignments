# Lab 2

## 1

> Assume that passwords are limited to the use of the 95 printable ASCII characters and that all passwords are 10 characters in length. Assume a password cracker with an encryption rate of 6.4 million encryptions per second. How long will it take to test exhaustively all possible passwords on a UNIX system?

$t=\frac{95^{10}}{6.4 \times 10^6} \approx 1.48 \times 10^5s$

## 2

> It was stated that the inclusion of the salt in the UNIX password scheme increases the difficulty of guessing by a factor of 4096. But the salt is stored in plaintext in the same entry as the corresponding ciphertext password. Therefore, those two characters are known to the attacker and need not be guessed.

### a)

> Why is it asserted that salt increases security?

因为它引入了随机性和唯一性，通过为每个密码加一个唯一的 Salt，即使两个用户选择了相同的密码，由于 Salt 的不同，它们的加密结果也会不同。这使得对密码的攻击变得更加困难，增加了破解的复杂性，即提高了安全性。

### b)

> Wouldn’t it be possible to completely thwart all password crackers by dramatically increasing the salt size to, say, 24 or 48 bits?

不能，增加 Salt 的位数可以提高密码的安全性，但并不能完全阻止所有密码破解器，破解者仍然可以暴力破解密码，只是需要更长的时间。

## 3

> In Unix, every process has a real user id (ruid), an effective user id (euid), and a saved user id (suid). Processes with an euid of 0 have special root privileges.
> Hints: Read the background components (Sec 3, 4, and 5.1) of [this research paper](https://www.usenix.org/legacy/publications/library/proceedings/sec02/full_papers/chen/chen.pdf).

### a)

>  If a process with user id x forks to create another process, what user id does the new process have? (Hint: it's the same answer for euid, ruid, and suid.)

$x$

### b)

> If a process with euid y makes a setuid system call, what possible euids can the process run with after the call, in each of the following situations:
> - Before: euid = y > 0, saved user id suid = m and real user id ruid = m. After:?
> - Before: y=0 After:?

- $m$
- Any valid user ID

### c)

> Each Android application runs in a separate process using a separate user id. From a security standpoint, what is the advantage of assigning separate uids instead of using the same uid for all? Explain.

In order to ensure that an app cannot access another app's data.

### d)

> The Android zygote process that creates new processes runs as root. After forking to create a new process, setuid is normally called. Explain what uid the new process has initially and why it is important to call setuid? What security purpose does this serve?

- The new process initially has **uid=0**, since it is forked from zygote whose uid=0.
- It is important to call `setuid`, because by changing the uid, we can **limit the new process's privilege** (Principle of least privilege).

### e)

> When a Unix user wishes to change her password, she uses the passwd program. The Unix password file is usually publicly readable but (for obvious reasons) can only be written by processes with root privileges.
> - How should the setuid bit be set on this passwd program? Explain how this lets a user change her password.
> - Why does this make it important to write the passwd program source code carefully?

- It should be set to `1`. Since the executable's owner is `root`, by setting the `setuid` bit to `1`, a user launched `passwd` process would have root privilege to modify `/etc/passwd`. If the `setuid` bit is not `1`, the user launched `passwd` process would not have the permission to modify password.
- If there's a bug, a common user might be able to change an arbitrary user's password, or read/write any given file, since the created `passwd` process has root privilege.

## 4

> Consider the following code snippet:
> ```c
> if (!stat("./file.dat", buf)) return; // abort if file exists
> sleep(10); // sleep for 10 seconds
> fp = fopen("./file.dat", "w"); // open file for write
> fprintf(fp, "Hello world");
> close(fp);
> ```

### a)

> Suppose this code is running as a setuid root program. Give an example of how this code can lead to unexpected behavior that could cause a security problem. Hint: try using symbolic links.

- If, when the program is sleeping, we execute: `ln -s /etc/passwd ./file.dat`
- Then, `/etc/passwd` might be overwritten

### b)

> Suppose the sleep(10) is removed from the code above. Could the problem you identified in part (a) still occur? Please explain.

- It might still occur, but under a much more constrained timing scenario.
- If the scheduler chooses to pause the program exactly after it has executed `if (!stat("./file.dat", buf)) return;`, and chooses to execute the `ln` command we've mentioned, then the attack will succeed.

### c)

> How would you fix the code to prevent the problem from part (a)?

- Using `setuid` to drop root privilege, if it is not required.
- Using atomic file operations, e.g. `int fd = open("./file.dat", O_WRONLY | O_CREAT | O_EXCL, 0666);`
- Explicitly check if the file is a symbolic link.

## 5

> The VAX/VMS operating system makes use of four processor access modes to facilitate the protection and sharing of system resources among processes. The access mode determines:
> - Instruction execution privileges: What instructions the processor may execute
> - Memory access privileges: Which locations in virtual memory the current instruction may access
> The four modes are as follows:
> - Kernel: Executes the kernel of the VMS operating system, which includes mem- ory management, interrupt handling, and I/O operations
> - Executive: Executes many of the operating system service calls, including file and record (disk and tape) management routines
> - Supervisor: Executes other operating system services, such as responses to user commands
> - User: Executes user programs, plus utilities such as compilers, editors, linkers, and debuggers
> A process executing in a less-privileged mode often needs to call a procedure that executes in a more-privileged mode; for example, a user program requires an operating system service. This call is achieved by using a change-mode (CHM) instruction, which causes an interrupt that transfers control to a routine at the new access mode. A return is made by executing the REI (return from exception or interrupt) instruction.

### a)

> A number of operating systems have two modes, kernel and user. What are the advantages and disadvantages of providing four modes instead of two?

- 优点：可以更精细地控制和访问权限和资源，提高系统的资源利用率和性能；在不同模式下运行的进程对彼此的资源访问受限，可以降低未经授权的访问或干扰的风险，提高系统安全性；
- 缺点：四种模式需要更详细地管理访问权限和资源，会增加系统的复杂性，使系统更难理解和维护；会引入额外的开销，包括上下文切换和管理模式之间的转换等，影响系统的性能。

### b)

> Can you make a case for even more than four modes?

例如 MULTICS OS 使用了七个操作系统层，虽然这一操作系统不是很成功，但它包含了很多现代操作系统的雏形，比如隐藏核心文件，只提供用户界面等，并且 MULTICS 直接孕育出了 UNIX。如今的许多处理器都支持 hypervisor 模式，也就是所谓的第 0 层，可以直接访问硬件，它通常与虚拟化软件如 VMware 一起使用。此外，较新的 AMD-V 处理器还推出了一个 -1 级，使得客户操作系统可以在第 0 层本地运行，而不会与其他客户操作系统发生冲突。

## 6

### a)

> In a Linux machine
> - generate a 16-byte hex string (e.g., using openssl rand),
> - take the first half of the hex string as the user name, create a user with the home directory,
> - and set up its password as the last half of the hex string (hints: commands useradd and passwd)

```shell
$ openssl rand -hex 16
d6f1a07c7502d98cbe9283a9afd5e0c3
$ sudo useradd -m -d /home/d6f1a07c7502d98c d6f1a07c7502d98c
$ sudo passwd d6f1a07c7502d98c
```

### b)

> Look into the passwd file (/etc/passwd), and locate the entry of your newly created user, Look into the file (/etc/shadow) storing the salted password hash, identify the entry for your newly created user X

```shell
$ cat /etc/passwd | grep d6f1a07c7502d98c
d6f1a07c7502d98c:x:1001:1001::/home/d6f1a07c7502d98c:/bin/sh
$ sudo cat /etc/shadow | grep d6f1a07c7502d98c
d6f1a07c7502d98c:$y$j9T$e8Bd3Gf/EGFwjGlevYpV20$QSPjZ4iGq08tFifLPpfk/vFsjq7cmXq2oDo/2iGtD17:19815:0:99999:7:::
```

### c)

> Understand the shadow entry format, parse out the salt, the salted password hash, as well as the hash algorithm

- Salt: `e8Bd3Gf/EGFwjGlevYpV20`
- Salted hash: `QSPjZ4iGq08tFifLPpfk/vFsjq7cmXq2oDo/2iGtD17`
- Hash algorithm: `yescrypt`

### d)

> Utilize openssl passwd to recalculate the password hash, and compare with the one stored in /etc/shadow

Openssl does not support `yescrypt`, so we have to use alternatives instead.

```shell
$ python3 -c 'import crypt; print(crypt.crypt("be9283a9afd5e0c3", "$y$j9T$e8Bd3Gf/EGFwjGlevYpV20$"))'
$y$j9T$e8Bd3Gf/EGFwjGlevYpV20$QSPjZ4iGq08tFifLPpfk/vFsjq7cmXq2oDo/2iGtD17
```

We can see that the calculated hash is the same as the one stored in `/etc/shadow`.

### e)

> Change the password for the user x, and redo d

```shell
$ sudo passwd d6f1a07c7502d98c # very_strong_password
$ sudo cat /etc/shadow | grep d6f1a07c7502d98c
d6f1a07c7502d98c:$y$j9T$vr1HF17Ht8EtpdCpUWrjW/$3KPKZHk0tcludhQPQLU9FzaMIX.mw2E2UcLCR/WAUMB:19815:0:99999:7:::
$ python3 -c 'import crypt; print(crypt.crypt("very_strong_password", "$y$j9T$vr1HF17Ht8EtpdCpUWrjW/$"))'
$y$j9T$vr1HF17Ht8EtpdCpUWrjW/$3KPKZHk0tcludhQPQLU9FzaMIX.mw2E2UcLCR/WAUMB
```

Again, we have verified the hash.

## 7

> Select and read one of the following papers, summarize its ideas, and give your critical reviews:
> - Backes, Michael, Sven Bugiel, Sebastian Gerling, and Philipp von Styp-Rekowsky. "Android security framework: Extensible multi-layered access control on android." In Proceedings of the 30th annual computer security applications conference, pp. 46-55. 2014. b)
> - Barth, Adam, Collin Jackson, Charles Reis, and TGC Team. "The security architecture of the chromium browser." In Technical report. Stanford University, 2008.

- 选择第二篇论文进行分析。这篇论文详细介绍了 Chromium 浏览器的安全架构，Chromium 采用模块化的设计，将浏览器内核和渲染引擎分隔到不同的保护域中，通过沙盒技术降低渲染引擎的权限，从而减轻攻击的严重性，同时不影响现有网站的兼容性。
- 在引言部分，作者指出当前大多数 Web 浏览器仍采用 1993 年 NCSA Mosaic 引入的单体架构，这种设计易受安全威胁，如一旦浏览器出现漏洞，攻击者可能利用此漏洞控制整个浏览器。Chromium 采用的模块化设计能有效隔离浏览器内核与网页渲染模块，即使后者被攻破，也难以直接影响整个系统。
- 其中 Chromium 的两大核心模块是浏览器内核和渲染引擎。浏览器内核处理与操作系统的交互和管理用户数据，而渲染引擎则处理网页内容的解析和显示，但运行在受限的沙盒环境中，大大降低了被攻破的风险。详细介绍了各组件的职责分配和交互方式，如 HTML 解析、JavaScript 执行等均在沙盒中进行，而文件读写、网络访问则由内核控制。
- 沙盒技术是 Chromium 安全架构的核心，用于限制渲染引擎的系统调用权限。详细描述了沙盒的实现机制，包括如何利用操作系统特性来隔离进程，以及沙盒的具体限制（如文件访问、进程创建等）。
- 文章最后，作者通过对比分析在 Internet Explorer、Firefox 和 Safari 中公开的漏洞，评估了 Chromium 架构对安全威胁的防护效果。结果显示，Chromium 的设计能够显著降低由渲染引擎引起的安全问题的影响，展示了架构的有效性。
- Chromium 的安全架构虑了安全性、兼容性和性能之间的平衡，其模块化和沙盒技术的应用在当时具有创新性，对浏览器安全领域产生了深远影响。也有一定待完善的方面，比如模块化和沙盒技术的引入可能仍然会引起某些特定场景下的兼容性问题，特别是与一些依赖深层系统调用的复杂网页或 Web 应用；沙盒中的进程需要与浏览器内核进行额外的通信来完成任务，这可能增加系统调用的延迟，降低性能；由于安全隔离，插件和扩展的运行可能受到限制等等。
