---
title: "Gunnar the Gatekeeper (vikeCTF 2023)"
summary: "Medium Reverse Engineering Challenge - patching"
description: "Medium Reverse Engineering Challenge - 223 points"
tags: [Reverse Engineering, vikeCTF2023, medium, writeup]
date: 2023-03-20T00:00:00-05:00
draft: false
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description

Ah, the mighty Gunnar the Gatekeeper! He welcomes you to his land, but he is unsure if you are worthy to have the sacred flag. Discover the secret to unlock access to this most prized possesion.

Given file: [GunnarTheGatekeeper](/vikectf-gunnar-the-gatekeeper/GunnarTheGatekeeper)

---

## Writeup
Start off by running `file` on our file. It is an unstripped ELF executable. 

![name](/vikectf-gunnar-the-gatekeeper/2023-03-20_01-15.png#center)

Well then we've already been rickrolled. (These guys are really good at their ASCII art)

But.. this looks like an awful lot like the [previous rev](https://dinari.ca/posts/vikectf/floating-viking-head/) challenge from vikeCTF where I used angr to get the flag. Let's see what Ghidra says.

![name](/vikectf-gunnar-the-gatekeeper/2023-03-20_01-33.png#center)

Okay let me just `ctrl+c` `ctrl+v` my [solve.py](/vikectf-floating-viking-head/solve.py) from the prev challenge, slap the success-fail addresses in there just like last time, change the file name annnnndd.. oh it doesn't work. It was worth the 2 mins of work anyways.

Let's try another 2 min method (this usually never works). I can see a `printflag()` function that seems to have no parameters.. no server connection.. all client-sided..

Looking inside the function, its all obfuscated, various calls to stacks and other functions.

But what if I just patch the program where on line 30, instead of `if iVar1 == 0` I make it `if iVar1 != 0 `? So change the `JNZ` instruction to `JZ` or in other words, make it so our invalid passphrase reaches the `printflag()` function.

```c
  if (iVar1 == 0) {
    fwrite("\nYou are unworthy. Here is your punishment:\n",1,0x2c,stderr);
    fwrite(&DAT_0010f420,1,0xe11,stderr);
  }
  else {
    fwrite("\nYou are worthy! Here is the flag, the pride of our people:\n\n",1,0x3d,stderr);
    print_flag();
  }
```

After doing so, Ghidra flipped the if and else's pseudocode and thats perfect. Export the program as an ELF, give it an incorrect flag annnddd..

&nbsp;

![name](/vikectf-gunnar-the-gatekeeper/2023-03-20_01-57.png#center)

We've successfully finessed the system.

## Flag

`vikeCTF{p4tC#_m3_l1k3_1_0F_uR_fR3Nc#_g1r!s}`

---

### Personal note
This was probably the easiest rev challenge that I've solved but somehow it was listed as a medium. Oh well

Watchout for some picoCTF and HTB Cyber Apocalypse writeups in the coming days!
