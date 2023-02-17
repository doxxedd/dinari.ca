import z3
s = z3.Solver()

enc = bytearray.fromhex("0E C9 9D B8 26 83 26 41 74 E9 26 A5 83 94 0E 63 37 37 37")
n = len(enc)
flag = [z3.Int(f'flag_{i}') for i in range(n)]
s.add([(flag[i] * 17) % 253 == enc[i] for i in range(n)])
s.check() == z3.sat
flag = bytes([s.model().eval(flag[i]).as_long() for i in range(n)]).decode()
print(flag)