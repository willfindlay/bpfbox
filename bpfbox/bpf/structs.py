#####################################
#  WARNING WARNING WARNING WARNING  #
#                                   #
#  Keep in sync with bpf_program.h  #
#                                   #
#  WARNING WARNING WARNING WARNING  #
#####################################

import ctypes as ct

# TODO: read this from linux/limits.h instead
PATH_MAX = 4096
# TODO: read this from linux/sched.h instead
TASK_COMM_LEN = 16

class BPFBoxPath(ct.Structure):
    """
    struct bpfbox_path
    """
    _fields_ = [
            ('path', ct.c_char * PATH_MAX),
            ]

class BPFBoxProfile(ct.Structure):
    """
    struct bpfbox_profile
    """
    _fields_ = [
            ('tail_call_index', ct.c_int),
            ('comm', ct.c_char * TASK_COMM_LEN),
            ]

class BPFBoxProcess(ct.Structure):
    """
    struct bpfbox_process
    """
    _fields_ = [
            ('pid', ct.c_uint32),
            ('profile_key', ct.c_uint64),
            ('enforcing', ct.c_uint8),
            ]
