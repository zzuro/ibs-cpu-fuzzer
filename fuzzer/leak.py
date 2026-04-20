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

DEVICE_NAME = "/dev/svm_ibs_dev"


def open_device() -> int:
    return os.open(DEVICE_NAME, os.O_RDWR)

def ioctl_ack_set(fd: int, value: int) -> None:
    rc = _ioctl(fd, FUZZ_IOC_ACK_SET, ctypes.byref(ctypes.c_uint64(value)))
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(ACK_SET) failed: {os.strerror(e)}")
    
if __name__ == "__main__":
    fd = open_device()
    ioctl_ack_set(fd, 1)
    os.close(fd)
