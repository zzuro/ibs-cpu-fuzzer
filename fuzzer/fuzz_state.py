import ctypes

MAX_INSN_LENGTH = 15

START = 0
INSTRUCTION = 1
MICROOP = 2



class VmcbSeg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("selector", ctypes.c_uint16),
        ("attrib",   ctypes.c_uint16),
        ("limit",    ctypes.c_uint32),
        ("base",     ctypes.c_uint64),
    ]

class VmcbSaveArea(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("es", VmcbSeg),
        ("cs", VmcbSeg),
        ("ss", VmcbSeg),
        ("ds", VmcbSeg),
        ("fs", VmcbSeg),
        ("gs", VmcbSeg),
        ("gdtr", VmcbSeg),
        ("ldtr", VmcbSeg),
        ("idtr", VmcbSeg),
        ("tr", VmcbSeg),

        ("reserved_0xa0", ctypes.c_uint8 * 42),
        ("vmpl", ctypes.c_uint8),
        ("cpl", ctypes.c_uint8),
        ("reserved_0xcc", ctypes.c_uint8 * 4),
        ("efer", ctypes.c_uint64),
        ("reserved_0xd8", ctypes.c_uint8 * 112),
        ("cr4", ctypes.c_uint64),
        ("cr3", ctypes.c_uint64),
        ("cr0", ctypes.c_uint64),
        ("dr7", ctypes.c_uint64),
        ("dr6", ctypes.c_uint64),
        ("rflags", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("reserved_0x180", ctypes.c_uint8 * 88),
        ("rsp", ctypes.c_uint64),
        ("s_cet", ctypes.c_uint64),
        ("ssp", ctypes.c_uint64),
        ("isst_addr", ctypes.c_uint64),
        ("rax", ctypes.c_uint64),
        ("star", ctypes.c_uint64),
        ("lstar", ctypes.c_uint64),
        ("cstar", ctypes.c_uint64),
        ("sfmask", ctypes.c_uint64),
        ("kernel_gs_base", ctypes.c_uint64),
        ("sysenter_cs", ctypes.c_uint64),
        ("sysenter_esp", ctypes.c_uint64),
        ("sysenter_eip", ctypes.c_uint64),
        ("cr2", ctypes.c_uint64),
        ("reserved_0x248", ctypes.c_uint8 * 32),
        ("g_pat", ctypes.c_uint64),
        ("dbgctl", ctypes.c_uint64),
        ("br_from", ctypes.c_uint64),
        ("br_to", ctypes.c_uint64),
        ("last_excp_from", ctypes.c_uint64),
        ("last_excp_to", ctypes.c_uint64),
        ("reserved_0x298", ctypes.c_uint8 * 72),
        ("spec_ctrl", ctypes.c_uint64),
    ]

class Insn(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("bytes", ctypes.c_uint8 * MAX_INSN_LENGTH),
        ("len",   ctypes.c_uint32),
    ]

class Inj(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("i", Insn),
        ("index", ctypes.c_int),
        ("last_len", ctypes.c_int),
    ]

class Range(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("start", Insn),
        ("end", Insn),
        ("started", ctypes.c_bool),
    ]

class Result(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("valid", ctypes.c_uint32),
        ("length", ctypes.c_int),
        ("ecxeption", ctypes.c_uint32),
    ]

class FuzzingOp(ctypes.c_int):
    pass


class FuzzerState(ctypes.Structure):
    _fields_ = [
        ("fuzz_mem1_host", ctypes.c_void_p),
        ("fuzz_mem1_guest", ctypes.c_void_p),
        ("fuzz_mem2_host", ctypes.c_void_p),
        ("fuzz_mem2_guest", ctypes.c_void_p),

        ("total_range", Range),
        ("inj", Inj),
        ("result", Result),

        ("current_op", FuzzingOp),      
        ("fetch_counter", ctypes.c_uint64),
        ("per_instruction_counter", ctypes.c_uint64),

        ("saved_state", VmcbSaveArea),

        ("file_open", ctypes.c_bool),
    ]