import os
import enum
from abc import ABC, abstractmethod

from bpfbox.utils import get_inode_and_device


# linux/fs.h
@enum.unique
class AccessMode(enum.IntFlag):
    MAY_EXEC = 0x01
    MAY_WRITE = 0x02
    MAY_READ = 0x04
    MAY_APPEND = 0x08


class Rule:
    def __init__(self):
        pass

    @abstractmethod
    def generate(self):
        pass


class FSRule(Rule):
    def __init__(self, path: str, mode: AccessMode):
        assert isinstance(path, str)
        assert isinstance(mode, AccessMode)
        assert os.path.exists(path)

        self.path = path
        self.mode = mode

    def generate(self):
        st_ino, st_dev = get_inode_and_device(self.path)
        # if our path is a directory, we want to allow the directory and all of
        # its immediate children to be opened
        # TODO: maybe change this behavior to allow more control
        if os.path.isdir(self.path):
            file_predicate = f'((inode == {st_ino} || parent_inode == {st_ino}) && st_dev == {st_dev})'
        else:
            file_predicate = f'(inode == {st_ino} && st_dev == {st_dev})'
        access_predicate = f'(acc_mode & {self.mode})'
        return f'({file_predicate} && {access_predicate})'
