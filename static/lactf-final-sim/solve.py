enc = ("0E", "C9", "9D", "B8", "26", "83", "26", "41", "74", "E9", "26", "A5", "83", "94", "0E", "63", "37", "37", "37")
flag = []
for hex in enc:
    dec = int(hex, 16)  # decimal representation of enc values (16 bits in a hex)
    x = 0
    while (((x * 17) % 253) != dec): x += 1  # finding what int would satisfy our dec
    flag.append(chr(x))  # adding the text representation of x to flag
print(''.join(flag))  # print flag
