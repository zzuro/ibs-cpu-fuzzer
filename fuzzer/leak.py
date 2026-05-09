from ioctl import _ioctl, _IOR, _IOW, _IO
from fuzz_state import *
from relayfs import *

import argparse
import os
import sys
import shutil
import signal
import subprocess
import time
from pathlib import Path
import ctypes
import shlex
import errno
import traceback
import multiprocessing as mp


FUZZ_IOC_GET_STATE = _IOR(ord('a'), ord('c'), FuzzerState)
FUZZ_IOC_SET_STATE = _IOW(ord('a'), ord('d'), FuzzerState)
FUZZ_IOC_OPEN_LOG = _IO(ord('a'), ord('e'))
FUZZ_IOC_CLOSE_LOG = _IO(ord('a'), ord('f'))
FUZZ_IOC_MOVE_NEXT_INSTR = _IO(ord('a'), ord('g'))
FUZZ_IOC_RESET_STATE = _IO(ord('a'), ord('i'))
FUZZ_IOC_SET_GLOBAL_FUZZ_STATE = _IOW(ord('a'), ord('j'), FuzzerStateSnapshot)
FUZZ_IOC_GET_GLOBAL_FUZZ_STATE = _IOR(ord('a'), ord('k'), FuzzerStateSnapshot)
FUZZ_IOC_ACK_SET = _IOW(ord('a'), ord('l'), ctypes.c_uint64)
FUZZ_IOC_SET_ARGS = _IOW(ord('a'), ord('m'), UserSpaceArgs)

DEVICE_NAME = "/dev/svm_ibs_dev"


def open_device() -> int:
    return os.open(DEVICE_NAME, os.O_RDWR)

def ioctl_ack_set(fd: int, value: int) -> None:
    rc = _ioctl(fd, FUZZ_IOC_ACK_SET, ctypes.byref(ctypes.c_uint64(value)))
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(ACK_SET) failed: {os.strerror(e)}")
    

def ioclt_set_args(fd: int, asid: int, vmsa_pa: int) -> None:
    args = UserSpaceArgs()
    args.asid = asid
    args.vmsa_pa = vmsa_pa
    args.fail = 1
    args.leak_rax = 1
    args.cpu = 4
    args.vmcb_pa = 0x124f56000
    rc = _ioctl(fd, FUZZ_IOC_SET_ARGS, ctypes.byref(args))
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(GET_ARGS) failed: {os.strerror(e)}")
    return args
    
if __name__ == "__main__":
    fd = open_device()
    ioclt_set_args(fd, 2, 0x124f4c000)
    ioctl_ack_set(fd, 0x1)
    os.close(fd)
