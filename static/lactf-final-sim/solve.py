import z3
s = z3.Solver()
enc = bytearray.fromhex("0E C9 9D B8 26 83 26 41 74 E9 26 A5 83 94 0E 63 37 37 37")
# Converting from hex to byte array
print(enc)
# placeholder list for flag
flag = [z3.Int(f'flag_{i}') for i in range(len(enc))]

# Adding our constraints/encoding operations
s.add([(flag[i] * 17) % 253 == enc[i] for i in range(len(enc))])
s.check()  # solve

flag = bytes([s.model().eval(flag[char]).as_long() for char in range(len(enc))]).decode()
print(flag)


# import angr, claripy
# success_adr = 0x0010141e
# fail_adr = 0x00101412
# proj = angr.Project('./finals_simulator')

# flag_list = [claripy.BVS('flag_%d' % i, 8) for i in range(18)]
# flag = claripy.Concat(*flag_list + [claripy.BVV(b'\n')])

# state = proj.factory.full_init_state(
#     args=['./finals_simulator'],
#     add_options=angr.options.unicorn,
#     stdin=flag

# )

# for k in flag_list:
#     state.solver.add(k >= ord('!'))
#     state.solver.add(k <= ord('~'))

# simgr = proj.factory.simulation_manager(state)
# simgr.explore(find=success_adr, avoid=fail_adr)

# if (len(simgr.found) > 0):
#     for found in simgr.found:
#         print(found.posix.dumps(0))


# enc = bytearray.fromhex("0E C9 9D B8 26 83 26 41 74 E9 26 A5 83 94 0E 63 37 37 37")
# inv = pow(17, -1, 253)

# s = []
# for hex in enc:
#     s.append((hex * inv) % 253)
# print(s)


# def algo(T, x):
#     if T is None:
#         return "Not found"
#     elif T.data == x:
#         return T.data
#     elif T.data < x:
#         return algo(T.right, x)
#     else:
#         if algo(T.left, x) != "Not found":
#             return T.data
#         else:
#             return algo(T.left, x)
