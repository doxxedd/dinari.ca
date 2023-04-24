---
title: "finals-simulator (LACTF 2023)"
summary: "Easy Reverse Engineering Challenge - my first write up!"
description: "Easy Reverse Engineering Challenge - 267 points"
tags: [Reverse Engineering, LACTF2023, easy, writeup]
date: 2023-02-20T20:29:33-05:00
draft: false
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description
Don't you love taking finals? Don't you wish you could do it not only during finals week, but during every week? Fret no more, Finals Simulator 2023 has got your back! If you install now and get an A+ on your simulated final, you'll even get the limited time Flag DLC for free! Also, after numerous reports of cheating we've installed an anti-cheating mechanism so people actually have to solve the problem.

Given file: [finals_simulator](/lactf-final-sim/finals_simulator)

---

## Writeup

We can start off by running the command `file ./finals_simulator` just to see what type of file we're working with here.

```text {linenos=false}
ELF 64-bit LSB pie executable, x86-64, ... not stripped
```

It's an executable **ELF** file and is **not stripped** meaning it still contains debugging info. So, it'll be easier for us to figure out what the program is doing later in Ghidra.

Let's run the program:

```text {linenos=false}
$ ./finals_simulator 
Welcome to Finals Simulator 2023: Math Edition!
Question #1: What is sin(x)/n? asd
Wrong! You failed.
```

Queue up **Ghidra**! If you are unfamiliar with [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases), it is a free  decompiler developed by the NSA (yeah the US one).

Upon opening, create a new non-shared project, and then hit `I` to import a file. After importing, double click the file and hit analyze. On the left side, locate `Symbol Tree -> Functions  -> main`

![name](/lactf-final-sim/2023-02-20-22-30-47.png#center)

We can see the `main` function in assembly in the middle of the screen, and a decompiled C pseudocode on the right (picture above). Immediately, the questions asked are visible.


```c {linenos=true}
undefined8 main(void)

{
  int iVar1;
  size_t sVar2;
  int local_11c;
  char input [264];
  char *i;
  
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
      for (i = input; *i != '\0'; i = i + 1) {
        *i = (char)((long)(*i * 0x11) % 0xfd);
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

#### Question 1
Line 16: there is a `strcmp()` which will set `iVar1` to `0` if the `local_118` is the same as **`six`**. There is our 1st answer, but lets also rename `local_118 -> input` (already applied above) so we can read the code better. (Select the text and hit `L` to rename)

#### Question 2
Line 21: we can see `local_11c` is being read and with some operations must equal `0x2179556a`. When it does, we see the next question. Right clicking these hex values reveals the decimals. 

All we have to do here is find x: `((x + 88) * 42 == 561599850)` which is **`13371337`**

#### Question 3
Let's look at the for loop on line 28. The counter seems to be `local_10` since `+1` is being added to it after iteration. Rename `local_10 -> i` (already applied above). So, the loop is basically iterating through all characters of input (notice `i = input`).

Inside the loop, the chars of our input is being encoded with various operations. Line 32: This encoded input now is being checked against `enc` and if they match, the `printflag()` reads a txt file containing the flag on the server (remember we connect to the server to get the flag).

Let's take a look at `enc` (double click it in the decompiler view):
![name](/lactf-final-sim/2023-02-17_02-54-31.png#center)

Looks like some sort of a hex array. We have to decode this based on line 29. 

```py
enc = ("0E", "C9", "9D", "B8", "26", "83", "26", "41", "74", "E9", "26", "A5", "83", "94", "0E", "63", "37", "37", "37")
flag = []
for hex in enc:
    dec = int(hex, 16)  # decimal representation of enc values (16 bits in a hex)
    x = 0
    while (((x * 17) % 253) != dec): x += 1  # finding what int would satisfy our dec
    flag.append(chr(x))  # adding the text representation of x to flag
print(''.join(flag))  # print flag
```
Output: `it's a log cabin!!!`

## Flag
After entering the answers `(six, 13371337, it's a log cabin!!!)`we get:
`lactf{im_n0t_qu1t3_sur3_th4ts_h0w_m4th_w0rks_bu7_0k}`

---

### Personal note

Just wanna end off by saying thank you for reading this, it was my first writeup and my entire inspiration to setup this website and do this writeup was thanks to [LACTF](https://lactf.uclaacm.com/) and [Boschko](https://boschko.ca/).
