---
title: "finals-simulator (LACTF 2023)"
summary: "Easy Reverse Engineering Challenge - my first write up!"
description: "Easy Reverse Engineering Challenge"
tags: [Reverse Engineering, CTF]
date: 2023-02-16T20:29:33-05:00
draft: false
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description
Don't you love taking finals? Don't you wish you could do it not only during finals week, but during every week? Fret no more, Finals Simulator 2023 has got your back! If you install now and get an A+ on your simulated final, you'll even get the limited time Flag DLC for free! Also, after numerous reports of cheating we've installed an anti-cheating mechanism so people actually have to solve the problem.

Connect to it at `nc lac.tf 31132`

Given file(s): [finals_simulator](/lactf-final-sim/finals_simulator)

---

## Writeup

We can start off by running the command `file ./finals_simulator` just to see what type of file we're working with here.

```text
ELF 64-bit LSB pie executable, x86-64, ... not stripped
```

It's an executable **ELF** file and is **not stripped** meaning it still contains debugging info. So, it'll be easier for us to figure out what the program is doing later in Ghidra.

Let's run the program:

```text
$ ./finals_simulator 
Welcome to Finals Simulator 2023: Math Edition!
Question #1: What is sin(x)/n? asd
Wrong! You failed.
```

Queue up Ghidra! If you are unfamiliar with [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases), it is a free  decompiler developed by the NSA (yeah the US one).

Upon opening, create a new non-shared project, and then hit `I` to import a file. After importing, double click the file and hit analyze. On the left side, locate `Symbol Tree -> Functions  -> main`

![name](/lactf-final-sim/2023-02-16_22-17.jpg#center)

We can see the `main` function in assembly in the middle, and a decompiled c code on the right (pasted below). Immediately, the questions asked are visible.

```C
undefined8 main(void)

{
  int iVar1;
  size_t sVar2;
  int local_11c;
  char input [264];
  char *local_10;
  
  puts("Welcome to Finals Simulator 2023: Math Edition!");
  printf("Question #1: What is sin(x)/n? ");
  fflush(stdout);
  fgets(input,0x100,stdin);
  sVar2 = strcspn(input,"\n");
  input[sVar2] = '\0';
  iVar1 = strcmp(input,"six");
  if (iVar1 == 0) {
    printf("Question #2: What\'s the prettiest number? ");
    fflush(stdout);
    __isoc99_scanf(&DAT_001020c3,&local_11c);
    if ((local_11c + 0x58) * 0x2a == 0x2179556a) {
      printf("Question #3: What\'s the integral of 1/cabin dcabin? ");
      fflush(stdout);
      getchar();
      fgets(input,0x100,stdin);
      sVar2 = strcspn(input,"\n");
      input[sVar2] = '\0';
      for (local_10 = input; *local_10 != '\0'; local_10 = local_10 + 1) {
        *local_10 = (char)((long)(*local_10 * 0x11) % 0xfd);
      }
      putchar(10);
      iVar1 = strcmp(input,enc);
      if (iVar1 == 0) {
        puts("Wow! A 100%! You must be really good at math! Here, have a flag as a reward.");
        print_flag();
      }
      else {
        puts("Wrong! You failed.");
      }
    }
    else {
      puts("Wrong! You failed.");
    }
  }
  else {
    puts("Wrong! You failed.");
  }
  return 0;
}
```
On line 16, there is a `strcmp()` which will set `iVar1` to `0` if the `local_118` is the same as **`six`**. There is our 1st answer, but lets also rename `local_118` to `input` so we can read the code better. (Do this by selecting the text and hitting `L`)

On line 21, we can see `local_11c` is being read and with some operations must equal `0x2179556a`. When it does, we see the next question. Right clicking these hex values reveals the decimals. All we have to do here is find x:
`((x + 88) * 42 == 561599850)` which is **`13371337`**

The next

## Solve.py

## Flag

---
Just wanna end off by saying thank you for reading this, it was my first writeup so, please suggest edits (top of the page).
