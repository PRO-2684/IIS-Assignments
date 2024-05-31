# Lab4

## 1

> Describe what a NOP sled is and how it is used in a buffer overflow attack.

A NOP sled is a sequence of `NOP` (No Operation) instructions used in exploit development, particularly in buffer overflow attacks. The `NOP` instruction does nothing and simply moves the instruction pointer to the next instruction in the sequence.

1. **Buffer Overflow Setup**: In a buffer overflow attack, an attacker attempts to overwrite the memory of an application by providing more input data than the buffer can handle.
2. **Placing the NOP Sled**: The attacker fills part of the overflowed buffer with a large number of `NOP` instructions. This is the NOP sled.
3. **Shellcode Placement**: Following the NOP sled, the attacker places the shellcode (malicious code) they want to execute.
4. **Overwriting the Return Address**: The attacker overwrites the return address on the stack with an address pointing to the NOP sled.

The purpose of the NOP sled is to **Increases Success Rate**. Since `NOP` instructions do nothing, the instruction pointer can *land* anywhere in the NOP sled and *slide down* to eventually reach and execute the shellcode.

## 2

> Look into different shellcodes released in [Packet Storm](https://packetstormsecurity.com/files/tags/shellcode/), and summarize different operations an attacker may design shellcode to perform.

1. 反向 Shell，允许攻击者打开一个反向连接，从目标机器连接回攻击者的机器，从而给予攻击者一个远程 shell 访问。
2. 绑定 Shell，在目标机器上开启一个端口并绑定一个 shell 到该端口，攻击者可以连接到这个端口并获得 shell 访问。
3. 从远程服务器下载恶意可执行文件并在目标系统上运行。
4. 可以在目标系统上创建一个新的用户账户，并赋予管理员权限。
5. 提升当前用户的权限，以获得更高的系统权限，如 root 权限。
6. 读取或修改目标系统内存中的数据，以窃取敏感信息或操纵程序的行为。
7. 针对操作系统内核进行攻击，以获得更高的系统控制权，甚至完全控制目标机器。

## 3

> Below is a simple C code with a buffer overflow issue.
>
> ```c
> #include <stdio.h>
> #include <string.h>
>
> int main(int argc, char *argv[]) {
>     int valid = false;
>     char str1[9] = "fdalfakl";
>     char str2[9];
>     printf("Input your password:\n");
>     gets(str2);
>     if (strncmp(str1, str2, 8) == 0) {
>         valid = true;
>         printf("Your exploit succeeds!\n");
>     }
>     printf("buffer1: str1(%s), str2(%s), valid(%d)\n", str1, str2, valid);
> }
> ```
>
> a. Craft a simple buffer overflow exploit, and circumvent the password checking logic. Include in your submission necessary step-by-step screenshots or descriptions to demonstrate how you carry out the attack.
> b. Describe how to fix this buffer overflow issue.

### a

![](attachments/Pasted%20image%2020240522145003.png)

### b

Fix: replace `gets(str2);` with `fgets(str2, 9, stdin);`.

![](attachments/Pasted%20image%2020240522145300.png)

## 4

> Elizabeth is attacking a buggy application. She has found a vulnerability that allows her to control the values of the registers ecx, edx, and eip, and also allows her to control the contents of memory locations 0x9000 to 0x9014. She wants to use return-oriented programming, but discovers that the application was compiled without any ret instructions! Nonetheless, by analyzing the application, she learns that the application has the following code fragments (gadgets) in memory:
>
> ```asm
> 0x3000:   add edx, 4     ; edx = edx + 4
>           jmp [edx]      ; jump to *edx
> 0x4000:   add edx, 4     ; edx = edx + 4
>           mov eax, [edx] ; eax = *edx
>           jmp ecx        ; jump to ecx
> 0x5000:   mov ebx, eax   ; ebx = eax
>           jmp ecx        ; jump to ecx
> 0x6000:   mov [eax], ebx ; *eax = ebx
>  ...                     ; don't worry about what happens after this
> ```
>
> Show how Elizabeth can set the values of the registers and memory so that the vulnerable application writes the value 0x3333 to memory address 0x6666.

设置寄存器和内存值如下

| Register |  Value   |
| :------: | :------: |
|  `ecx`   | `0x5000` |
|  `edx`   | `0x8FFC` |
|  `eip`   | `0x4000` |

| Memory Address |  Value   |
| :------------: | :------: |
|    `0x9000`    | `0x6666` |
|    `0x9004`    | `0x6000` |
|    `0x9008`    |   N/A    |
|    `0x900c`    |   N/A    |
|    `0x9010`    |   N/A    |
|    `0x9014`    |   N/A    |

## 5

> Consider the following simplified code that was used earlier this year in a widely deployed router. If hdr->ndata = "ab" and hdr->vdata = "cd" then this code is intended to write "ab:cd" into buf. Suppose that the attacker has full control of the contents of hdr. Explain how this code can lead to an overflow of the local buffer buf.
>
> ```c
> uint32_t nlen, vlen;
> char buf[8264];
> nlen = 8192;
> if ( hdr->nlen <= 8192 ){
>     nlen = hdr->nlen;
> }
> memcpy(buf, hdr->ndata, nlen);
> buf[nlen] = ':';
> vlen = hdr->vlen;
> if (8192 - (nlen+1) <= vlen){ /* DANGER */
>     vlen = 8192 - (nlen+1);
> }
> memcpy(&buf[nlen+1], hdr->vdata, vlen);
> buf[nlen + vlen + 1] = 0;
> ```

If we assign `hdr->nlen = 8192` and `hdr->vlen=8192`, we can make this code crash. When the program executes the check `8192 - (nlen+1) <= vlen`, since `nlen = 8192`, `8192 - (nlen+1)` would give us `-1`. But `vlen` is of type `uint32_t`, so the left value would underflow to $2^{32}-1$, which is effectively greater than our `vlen`, allowing us to bypass the check. Thus, the buffer would overflow.

Example code:

```c
#include <stdint.h>
#include <string.h>
#include <stdio.h>

struct Header {
    uint32_t nlen;
    uint32_t vlen;
    char ndata[8192];
    char vdata[8192];
};

void vulnerable(struct Header *hdr) {
    uint32_t nlen, vlen;
    char buf[8264];
    nlen = 8192;
    if (hdr->nlen <= 8192) {
        nlen = hdr->nlen;
    }
    memcpy(buf, hdr->ndata, nlen);
    buf[nlen] = ':';
    vlen = hdr->vlen;
    if (8192 - (nlen + 1) <= vlen) { /* DANGER */
        vlen = 8192 - (nlen + 1);
    }
    memcpy(&buf[nlen + 1], hdr->vdata, vlen);
    buf[nlen + vlen + 1] = 0;
    printf("%s\n", buf);
}

void normal() {
    struct Header h;
    h.nlen = 8;
    h.vlen = 8;
    h.ndata[0] = 'A';
    h.ndata[1] = 'B';
    h.ndata[2] = 'C';
    h.ndata[3] = 'D';
    h.ndata[4] = 'E';
    h.ndata[5] = 'F';
    h.ndata[6] = 'G';
    h.ndata[7] = 'H';
    h.vdata[0] = 'I';
    h.vdata[1] = 'J';
    h.vdata[2] = 'K';
    h.vdata[3] = 'L';
    h.vdata[4] = 'M';
    h.vdata[5] = 'N';
    h.vdata[6] = 'O';
    h.vdata[7] = 'P';
    vulnerable(&h);
}

void attack() {
    struct Header h;
    h.nlen = 8192;
    h.vlen = 8192;
    memset(h.ndata, 'A', 8192);
    memset(h.vdata, 'B', 8192);
    vulnerable(&h);
}

int main() {
    puts("normal():");
    normal();
    puts("attack():");
    attack();
    puts("Attack failed!");
    return 0;
}
```

![](attachments/Pasted%20image%2020240522154149.png)

## 6

> Select one from the research papers listed below and conduct a critical review.
>
> - Kocher, Paul, Jann Horn, Anders Fogh, Daniel Genkin, Daniel Gruss, Werner Haas, Mike Hamburg et al. "Spectre attacks: Exploiting speculative execution." Communications of the ACM 63, no. 7 (2020): 93-101.
> - Garfinkel, Tal, Ben Pfaff, and Mendel Rosenblum. "Ostia: A Delegating Architecture for Secure System Call Interposition." In NDSS. 2004.

选择 Kocher，Paul 等人撰写的《Spectre Attacks: Exploiting Speculative Execution》一文。本文深入探讨了现代处理器中存在的重大漏洞，这些漏洞利用了 speculative execution 这一在大多数高速处理器中常见的性能优化技术。作者详细说明了攻击者如何诱导处理器执行本不应该执行的指令，从而通过侧信道泄露机密信息，首次展示了绕过传统安全机制的实际攻击，对包括 Intel、AMD 和 ARM 在内的多家厂商的处理器都产生了影响​​。

Advantages:

1. 论文提供了对投机执行机制及其可能被利用的详细分析，包括对分支预测和乱序执行的描述，使得不同背景的读者都能理解这些复杂概念。
2. 通过展示 Spectre 漏洞不仅限于单一厂商的处理器，论文强调了这些漏洞对整个行业的广泛影响，这对于业界具有重要意义。
3. 作者展示了现实世界中的攻击，并提供了概念验证实现。这种实用性的方法强调了处理这些漏洞的紧迫性，有助于理解 Spectre 攻击的实际风险。
4. 论文不仅识别出漏洞，还讨论了潜在的缓解措施，包括软件补丁和硬件更改，为开发综合性的安全解决方案提供了指导。

Weaknesses or limitations:

1. 虽然论文提出了几种缓解策略，但许多策略较为复杂，可能需要对现有硬件和软件进行重大更改，这对快速部署和采用构成障碍。
2. 所建议的缓解措施通常伴随性能上的权衡。例如，禁用投机执行或实施更严格的检查可能会降低处理器性能，这对高性能计算环境是一个重要的考虑因素。
3. 尽管论文在分析上很彻底，但主要侧重于高层概念和实际演示，缺乏详细的低层次技术细节，这对于那些希望开发和实施精确对策的研究人员和专业人士来说是不利的。
