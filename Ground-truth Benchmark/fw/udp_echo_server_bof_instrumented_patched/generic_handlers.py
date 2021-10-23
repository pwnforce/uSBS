from unicorn.arm_const import *
import signal
import os
from ...exit import do_exit

# cp ./generic_handlers.py /home/halfuzz/hal-fuzz/hal_fuzz/hal_fuzz/handlers/generic/__init__.py


def return_zero(uc):
    uc.reg_write(UC_ARM_REG_R0, 0)

def crash(uc):
    print("[*] Crashing handler at 0x{:08x} triggered, crashing now".format(uc.reg_read(UC_ARM_REG_PC)))
    os.kill(os.getpid(), signal.SIGSEGV)

def exit(uc):
    print("[*] exit block hook invoked at {:08x}".format(uc.reg_read(UC_ARM_REG_PC)))
    do_exit(0)

def hello(uc):
    print("[*] hello from test handler at {:08x}".format(uc.reg_read(UC_ARM_REG_PC)))

def hello_hello(uc):
    print("[*] hello hello from test handler at {:08x}".format(uc.reg_read(UC_ARM_REG_PC)))

def hal_assert(uc, msg, cond):
    if not cond:
        print("Assertion failed: {}".format(msg))
        crash(uc)