---
title: "Simple Stack Smash (SummitCTF 2023)"
summary: "Easy pwn Challenge - using pwndbg"
description: "Easy pwn Challenge - 100 points"
tags: [pwn, SummitCTF2023, easy, writeup]
date: 2023-04-21T22:00:00-05:00
draft: true
searchHidden: false
ShowToc: true
TocOpen: false
hidemeta: false
# weight: 1
---

## Description

Can you perform a simple stack smash? I hope so, you'll need to in order to reach the summit...

Use ```nc 0.cloud.chals.io 24579``` to connect

Given file: [simple-stack-smash](/summitctf-simple-stack-smash/simple-stack-smash)

---

## Writeup

I'm going to use GDB with the [pwndbg](https://github.com/pwndbg/pwndbg) plugin for this challenge. Run ```gdb <file>```.




## Flag

`summitCTF{G1mMI3_S0M3th1NG_H4rD3r_PlZ}`

---
### Personal note
