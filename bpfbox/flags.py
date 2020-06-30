from enum import Enum, unique, _decompose, Flag as _Flag


class Flag(_Flag):
    """
    enum.Flag but with better printing
    """
    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return '%s' % (self._name_)
        members, uncovered = _decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return '%r' % (members[0]._value_)
        else:
            return '|'.join([str(m._name_ or m._value_) for m in members])



@unique
class BPFBOX_ACTION(Flag):
    ACTION_NONE = 0x0
    ACTION_AUDIT = 0x1
    ACTION_ALLOW = 0x2
    ACTION_TAINT = 0x4
    ACTION_DENY = 0x8
    ACTION_COMPLAIN = 0x10


@unique
class FS_ACCESS(Flag):
    MAY_EXEC = 0x00000001
    MAY_WRITE = 0x00000002
    MAY_READ = 0x00000004
    MAY_APPEND = 0x00000008
    MAY_ACCESS = 0x00000010
    MAY_OPEN = 0x00000020
    MAY_CHDIR = 0x00000040
    MAY_NOT_BLOCK = 0x00000080
