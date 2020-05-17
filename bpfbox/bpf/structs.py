#####################################
#  WARNING WARNING WARNING WARNING  #
#                                   #
#  Keep in sync with bpf_program.h  #
#                                   #
#  WARNING WARNING WARNING WARNING  #
#####################################

import ctypes as ct


class BPFBoxProfileStruct(ct.Structure):
    _fields_ = (('tail_call_index', ct.c_int),)
