# Lab 2

## 1

> Assume that passwords are limited to the use of the 95 printable ASCII characters and that all passwords are 10 characters in length. Assume a password cracker with an encryption rate of 6.4 million encryptions per second. How long will it take to test exhaustively all possible passwords on a UNIX system?

## 2

> It was stated that the inclusion of the salt in the UNIX password scheme increases the difficulty of guessing by a factor of 4096. But the salt is stored in plaintext in the same entry as the corresponding ciphertext password. Therefore, those two characters are known to the attacker and need not be guessed.

### a)

> Why is it asserted that salt increases security?

### b)

> Wouldn’t it be possible to completely thwart all password crackers by dramatically increasing the salt size to, say, 24 or 48 bits?

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

>     Suppose this code is running as a setuid root program. Give an example of how this code can lead to unexpected behavior that could cause a security problem. Hint: try using symbolic links.

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

### b)

> Can you make a case for even more than four modes?

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



