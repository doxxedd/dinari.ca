import angr
import claripy

base_adr = 0x00100000
success_adr = 0x00101245
fail_adr = 0x0010126f
flag_len = 27  # 39

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
