---
title: "Rewrite It In Zig (amateursCTF 2025)"
summary: "Medium Pwn Challenge - BOF in Zig + ROPchains"
description: "Medium Pwn Challenge - BOF in Zig + ROPchains"
tags: [PWN, medium, writeup, rop, bof]
date: 2025-11-18T23:00:00-05:00
draft: false
searchHidden: false
ShowToc: true
TocOpen: true
hidemeta: false
# weight: 1
---

## Description

Sometimes rust is just a little too safe for me.

Given file: [rewrite-it-zig.tar.gz](/amateursctf-rewrite-it-in-zig/rewrite-it-zig.tar.gz)

---

## Writeup

### Initial Analysis

This challenge is written in [Zig](https://ziglang.org/) and the given source code is:

```zig {linenos=true}
const std = @import("std");
const print = std.debug.print;

pub fn main() void {
    print("you can never have too much zig pwn.\n", .{});

    var backing: [0x100]u8 = undefined;
    var buf: []u8 = &backing;
    buf.len = 0x1000;
    _ = std.io.getStdIn().read(buf) catch {};
}
```

We can see 0x100 or 256 bytes are being allocated on the stack however buffer length is set 
to 0x1000 (4096 bytes). This allows user to input 4096 bytes into a 256-byte buffer.

![name](/amateursctf-rewrite-it-in-zig/2025-11-17-233231.png#center)
Checksec reveals that we have NX enabled so the stack is non-executable. No injecting shellcode here,
instead we have to use Return-Oriented-Programming (ROP). PIE being disabled makes everything easier
as our ROP gadgets and BSS data segment will be at a constant address. We have to verify if the stack
canary actually exists since Zig binaries handle stack protection differently than C and also bof
might bypass the canary depending on the stack layout (we'll come back to this).


### Finding Offset
Lets how many bytes we have to send before we hit the RSP and the return address:
- `pwndbg chal`
- `cyclic 500` (copy this)
- Run the binary `r` then pass the cyclic pattern
- Check what RSP is (the last thing that was on the stack causing the seg fault)
- `cyclic -o uaaaaaab` return offset at **360** (-8 for RBP which we wanna control = **352**)
![name](/amateursctf-rewrite-it-in-zig/2025-11-21-163553.png#center)

### Finding ROP Gadgets
The goal is to call `execve("/bin/sh", 0, 0)` ([man page](https://man7.org/linux/man-pages/man2/execve.2.html)) and get a shell so it would've been nice if we had the string "/bin/sh" somewhere in the binary (we don't)  which we could just call here after our padding. `strings | grep '/bin/sh'` doesn't return anything.

So 


## Solve script
Completing the script:
```py {linenos=true}
#!/usr/bin/python3
from pwn import *

```

### Flag

`amateursCTF{i_love_zig_its_my_favorite_language_and_you_will_never_escape_the_zig_pwn_ahahaha}`

---