---
title: "Floating Viking Head (vikeCTF 2023)"
summary: "Easy Rev Challenge - using Angr"
description: "Easy Rev Challenge - using Angr"
tags: [REV, easy, writeup, angr]
date: 2023-03-19T20:02:00-05:00
draft: false
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description

Greetings, mere mortal! Are you ready to embark on a journey to unveil the flag and gain the wisdom of the floating Viking head? Harness the power of the oracle's gaze and use his words to guide you towards victory. (100 points)

Given file: [FloatingVikingHead](/vikectf-floating-viking-head/FloatingVikingHead)

---

## Writeup
Running `file` on our file tells us that it is an unstripped ELF executable. Running it reveals the following:
![name](/vikectf-floating-viking-head/2023-03-19_18-52.png#center)

Cool ASCII art, but this shows me that this challenge is a prime candidate for the use of [angr](https://angr.io/). Anytime where the program hits a failure and success point, `angr` could be used to solve for the flag.

Opening Ghidra, and looking inside the main method shows us everything we need: the success address, failure address, and base address. Let me explain.

```c {linenos=true}
bool main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf(
        "     _.-._\n   .\' | | `.\n  /   | |   \\\n |    | |    |\n |____|_|____|\n |____(_)____|\n  /|(o)| |(o)|\\\n//|   | |   |\\\\\n\'/|  (|_|)  |\\`\n //.///|\\\\\\.\\\\\n /////---\\\\\\\ \\\\n ////|||||\\\\\\\\\n \'//|||||||\\\\`\n   \'|||||||`\n\nI am the flag oracle.\nEnter a  flag and I will tell you if it is correct.\nFlag: "
        );
  iVar1 = 0x1c;
  fgets(local_38,0x1c,stdin);
  encrypt(local_38,iVar1);
  iVar1 = memcmp(&DAT_00102008,local_38,0x1b);
  if (iVar1 != 0) {
    fwrite("Failure, your input does not match the flag :(\n",1,0x2f,stderr);
  }
  else {
    fwrite("Success, your input matches the flag :)\n",1,0x28,stderr);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return iVar1 != 0;
}
```

`success_addr` = line 21, the address of the call to the `fwrite` function

`fail_addr` = line 18, the address of the call to the `fwrite` function

To find an address of a function, simply click on the name of the function and the corresponding assembly code will be revealed

`base_addr` = scroll ALL the way up to the beginning of the assembly code in Ghidra (usually it's 00100000)
![name](/vikectf-floating-viking-head/2023-03-19_19-47.png#center)

`flag_len` = this could just be the length of the char array (40), line 6. But, if you really wanna get it fully accurate then open `encrypt()` that reveals:
```c {linenos=true}
void encrypt(char *__block,int __edflag)

{
  ulong local_10;
  
  for (local_10 = 0; local_10 < 0x1b; local_10 = local_10 + 1) {
    __block[local_10] = __block[local_10] ^ 0x5d;
  }
  return;
}
```
This is a for loop iterating through the chars of our input with `local_10` being `i`. `local_10 < 0x1b` is `i < 27`. So our flag is maximum 27 in length.

&nbsp;

Slap all our findings in an angr template or write your own (GIGACHAD move) and run it! (just make sure your binary file is in the same folder as the python file)

```py
import angr
import claripy

base_adr = 0x00100000
success_adr = 0x00101245
fail_adr = 0x0010126f
flag_len = 27  # 40

flag_chars = [claripy.BVS(f"flag_char{i}", 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])

# angr boilerplate
project = angr.Project("./FloatingVikingHead", main_opts={"base_addr": base_adr})
state = project.factory.full_init_state(
    args=["./FloatingVikingHead"],
    add_options=angr.options.unicorn,
    stdin=flag
)

sim_manager = project.factory.simulation_manager(state)
sim_manager.explore(find=success_adr, avoid=fail_adr)

# adding only printable chars
for c in flag_chars:
    state.solver.add(c >= ord("!"))
    state.solver.add(c <= ord("~"))

# using stdin file descriptor to interact with program
if len(sim_manager.found) > 0:
    for found in sim_manager.found:
        print(found.posix.dumps(0))

```



## Flag
`vikeCTF{n0_57R1n95_F0r_Y0u}` [solve.py](/vikectf-floating-viking-head/solve.py)

---

### Personal note

I am by no means an angr expert, but I got the flag using a typical angr template in 5 mins. Mastering angr could mean you would be solving a LOT of rev challanges with ease and I really wanna work towards that. 
