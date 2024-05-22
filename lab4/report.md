# Lab4

## 1

> Describe what a NOP sled is and how it is used in a buffer overflow attack.

## 2

> Look into different shellcodes released in [Packet Storm](https://packetstormsecurity.com/files/tags/shellcode/), and summarize different operations an attacker may design shellcode to perform.

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
> if (8192 - (nlen+1) <= vlen ){ /* DANGER */
>     vlen = 8192 - (nlen+1);
> }
> memcpy(&buf[nlen+1], hdr->vdata, vlen);
> buf[nlen + vlen + 1] = 0;
> ```

## 6

> Select one from the research papers listed below and conduct a critical review.
>
> - Kocher, Paul, Jann Horn, Anders Fogh, Daniel Genkin, Daniel Gruss, Werner Haas, Mike Hamburg et al. "Spectre attacks: Exploiting speculative execution." Communications of the ACM 63, no. 7 (2020): 93-101.
> - Garfinkel, Tal, Ben Pfaff, and Mendel Rosenblum. "Ostia: A Delegating Architecture for Secure System Call Interposition." In NDSS. 2004.

