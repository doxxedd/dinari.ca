---
title: "Rewrite It In Zig (amateursCTF 2025)"
summary: "Medium pwn Challenge - BOF in Zig + ROPchains"
description: "Medium pwn Challenge - BOF in Zig + ROPchains"
tags: [PWN, medium, writeup, rop, bof]
date: 2025-11-18T23:00:00-05:00
draft: false
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description

Sometimes rust is just a little too safe for me.

Given file: [rewrite-it-zig.tar.gz](/amateursctf-rewrite-it-in-zig/rewrite-it-zig.tar.gz)

---

## Writeup

### Initial Analysis

This challenge is written in Zig and the given source code is:

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

Checksec reveals that we have NX enabled meaning 
![name](/amateursctf-rewrite-it-in-zig/2025-11-17-233231.png#center)


## Solve script
Completing the script:
```py {linenos=true}
#!/usr/bin/python3
from pwn import *

```

### Flag

`amateursCTF{i_love_zig_its_my_favorite_language_and_you_will_never_escape_the_zig_pwn_ahahaha}`

---