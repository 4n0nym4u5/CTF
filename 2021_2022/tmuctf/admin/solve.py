#!/usr/bin/python3

win_string=b'inctfj'

# This challenge could, in theory, be solved in multiple ways. However, for the
# sake of learning how to simulate an alternate filesystem, please solve this
# challenge according to structure provided below. As a challenge, once you have
# an initial solution, try solving this in an alternate way.
#
# Problem description and general solution strategy:
# The binary loads the password from a file using the fread function. If the
# password is correct, it prints "Good Job." In order to keep consistency with
# the other challenges, the input from the console is written to a file in the 
# ignore_me function. As the name suggests, ignore it, as it only exists to
# maintain consistency with other challenges.
# We want to:
# 1. Determine the file from which fread reads.
# 2. Use Angr to simulate a filesystem where that file is replaced with our own
#    simulated file.
# 3. Initialize the file with a symbolic value, which will be read with fread
#    and propogated through the program.
# 4. Solve for the symbolic input to determine the password.

import angr
import claripy
import os
import sys

def trace_with_file():
    target_program = './areyouadmin'
    poc_name = os.path.abspath(os.getcwd() + '/flag.txt')

    with open(poc_name, 'rb') as f:
        poc_contents = f.read()

    project = angr.Project(target_program, use_sim_procedures=True, auto_load_libs=False)

    # Given content looks like it preconstrains
    simfile = angr.SimFile(poc_name, content=poc_contents)

    state = project.factory.entry_state()

    
    # Start getting states of the execution
    simgr = state.project.factory.simulation_manager(state)
    # a=simgr.explore(find=lambda s: win_string in s.posix.dumps(1))
    # s = simgr.found[0]
    # print(s.posix.dumps(0))

    executed_states = []
    while simgr.active:
        if project.loader.main_object.contains_addr(simgr.active[0].addr):
            executed_states.append(simgr.active[0].copy())
            print(state.posix.dumps(sys.stdin.fileno()))
        if len(simgr.active) > 1:
            print(state.posix.dumps(sys.stdin.fileno()))
        simgr.step()

    # print("Done!")
    # print(len(executed_states))
    # ipdb.set_trace()
    # return executed_states

if __name__ == '__main__':
    trace_with_file()
