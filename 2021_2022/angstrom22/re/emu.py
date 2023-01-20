from qiling import *

# sandbox to emulate the EXE
def my_sandbox(path, rootfs):
    # setup Qiling engine
    ql = Qiling(path, rootfs)
    # now emulate the EXE
    ql.run()

if __name__ == "__main__":
    # execute Windows EXE under our rootfs
    my_sandbox(["./flatland"], "/home/init0/qiling/rootfs/x8664_linux")