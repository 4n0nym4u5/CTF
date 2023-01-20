#!/usr/bin/env python3
#!/usr/bin/env python
import angr
import claripy
import sys, time
import logging


def main(argv):
    path_to_binary = argv[1]
    base = 0x400000
    print("[] loading the binary")
    project = angr.Project(
        path_to_binary, main_opts={"base_addr": base}, auto_load_libs=False
    )
    logging.getLogger("angr.sim_manager").setLevel("INFO")
    length = 41
    begin = time.time()
    characters = [claripy.BVS("flag{-%d" % i, 8) for i in range(length)]
    input_ = claripy.Concat(*characters + [claripy.BVV(b"\n")])

    state = project.factory.full_init_state(
        args=[path_to_binary, input_], add_options=angr.options.unicorn
    )
    for x in characters:
        state.solver.add(x <= 127, x >= 32, x != 0)

    simulate = project.factory.simulation_manager(state)
    success = [0x000000000000146E]
    failure = [0x0000000000001493]
    simulate.explore(find=success, avoid=failure)

    y = []
    for z in simulate.deadended:
        if b"flag" in z.posix.dumps(1):
            y.append(z)
            print(y)

    valid = y[0].posix.dumps(0)
    flag = valid.decode("utf-8")
    print("[] Found flag:", flag)
    print("({} secs)".format(round(time.time() - begin, 2)))


if __name__ == "__main__":
    main(sys.argv)
