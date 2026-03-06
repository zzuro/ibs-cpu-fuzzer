import ctypes

IBS_REC_INVALID = 1
IBS_REC_HPA = 2
IBS_REC_EVENT = 3

IBS_OP_LOAD = 1
IBS_OP_STORE = 2
IBS_OP_BRANCH = 3


memwithStrings = ["0","1", "2", "4", "8", "16", "32", "64", "?8", "?9", "?A", "?B", "?C", "?D", "?C", "?E", "?F"]


class IbsRecordHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("record_type", ctypes.c_uint32),
        ("record_len", ctypes.c_uint16),
        ("instruction_len", ctypes.c_uint16),
        ("instruction", ctypes.c_uint8 * 16),
    ]

class IbsHpaRecord(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr", IbsRecordHeader),
        ("hpa", ctypes.c_uint64),
    ]

class IbsEventRecord(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr", IbsRecordHeader),

        ("rip", ctypes.c_uint64),
        ("uop_cnt", ctypes.c_uint64),

        ("phys_addr", ctypes.c_uint64),
        ("lin_addr", ctypes.c_uint64),
        ("branch_target_rip", ctypes.c_uint64),

        ("rax", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rdi", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r15", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("rbp", ctypes.c_uint64),
        ("rflags", ctypes.c_uint64),

        ("op_type", ctypes.c_uint32),
        ("mem_width", ctypes.c_uint32),

        ("dc_uc_mem_acc", ctypes.c_uint8),
        ("dc_wc_mem_acc", ctypes.c_uint8),
        ("dc_miss", ctypes.c_uint8),
        ("op_microcode", ctypes.c_uint8),
        ("op_brn_fuse", ctypes.c_uint8),
        ("op_brn_ret", ctypes.c_uint8),
        ("op_brn_misp", ctypes.c_uint8),
        ("op_brn_taken", ctypes.c_uint8),
    ]

HEADER_SIZE = ctypes.sizeof(IbsRecordHeader)
HPA_SIZE = ctypes.sizeof(IbsHpaRecord)
EVENT_SIZE = ctypes.sizeof(IbsEventRecord)