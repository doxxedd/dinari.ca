import z3
s = z3.Solver()

# Converting from hex to byte array
enc = bytearray.fromhex("0E C9 9D B8 26 83 26 41 74 E9 26 A5 83 94 0E 63 37 37 37")

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
# base_adr = 0x00100000
# flag_len = 18
# proj = angr.Project('./finals_simulator', main_opts={"base_addr": base_adr})

# flag_list = [claripy.BVS('flag_%d' % i, 8) for i in range(flag_len-1)]
# flag = claripy.Concat(*flag_list + [claripy.BVV(b'\n')])

# state = proj.factory.full_init_state(
#     args=['./finals_simulator'],
#     add_options=angr.options.unicorn,
#     stdin=flag
# )

# simgr = proj.factory.simulation_manager(state)
# simgr.explore(find=success_adr, avoid=fail_adr)

# if (len(simgr.found) > 0):
#     for found in simgr.found:
#         print(found.posix.dumps(0))