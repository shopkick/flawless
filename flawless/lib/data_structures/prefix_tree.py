#!/usr/bin/env python
#
# Copyright (c) 2011-2013, Shopkick Inc.
# All rights reserved.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# ---
# Author: John Egan <jwegan@gmail.com>

import os

from flawless.lib.data_structures import ProxyContainerMethodsMetaClass


class PrefixTree(object):
    __metaclass__ = ProxyContainerMethodsMetaClass
    _proxyfunc_ = lambda attr, self, *args, **kwargs: getattr(self.root, attr)(*args, **kwargs)

    def __init__(self, split_key_func, join_key_func, accumulator_func=None,
                 accumulator_intializer=None):
        self.split_key_func = split_key_func
        self.join_key_func = join_key_func
        self.accumulator_func = accumulator_func or (lambda x, y: x)
        self.accumulator_intializer = accumulator_intializer
        self.root = Branch(self)
        self.length = 0

    def set_accumulator(self, accumulator_func, accumulator_intializer):
        self.accumulator_func = accumulator_func
        self.accumulator_intializer = accumulator_intializer


class StringPrefixTree(PrefixTree):

    def __init__(self, accumulator_func=None, accumulator_intializer=None):
        split_key_func = lambda s: (s[0], s[1:])
        join_key_func = lambda *args: "".join(args)
        super(StringPrefixTree, self).__init__(
            split_key_func=split_key_func,
            join_key_func=join_key_func,
            accumulator_func=accumulator_func,
            accumulator_intializer=accumulator_intializer,
        )


class FilePathTree(PrefixTree):

    def __init__(self, accumulator_func=None, accumulator_intializer=None, sep=os.sep):
        split_key_func = lambda s: (s, None) if sep not in s else s.split(sep, 1)
        join_key_func = lambda *args: sep.join(*args)
        super(FilePathTree, self).__init__(
            split_key_func=split_key_func,
            join_key_func=join_key_func,
            accumulator_func=accumulator_func,
            accumulator_intializer=accumulator_intializer,
        )


class Branch(object):

    def __init__(self, trunk):
        self.trunk = trunk
        self.branches = dict()
        self.size = 0
        self.value = None
        self.is_set = False

    def __str__(self):
        retval = []
        if self.is_set:
            retval.append("(%s)" % str(self.value))

        for index, (key, subbranch) in enumerate(self.branches.items()):
            pad = "|     " if index != (len(self.branches) - 1) else "        "
            subbranch_str = "\n".join([pad + s for s in str(subbranch).split("\n")])
            retval.append("|-- " + str(key))
            retval.append(subbranch_str)
        return "\n".join(retval)

    def __setitem__(self, key, value):
        if not key:
            retval = not self.is_set
            self.value = value
            self.is_set = True
            self.size += 1
            return retval

        head, remaining = self.trunk.split_key_func(key)
        if head not in self.branches:
            self.branches[head] = Branch(self.trunk)
        retval = self.branches[head].__setitem__(remaining, value)
        self.size += int(retval)
        return retval

    def __getitem__(self, key):
        if not key:
            if self.trunk.accumulator_intializer is None:
                return self.value
            else:
                return self.trunk.accumulator_func(self.trunk.accumulator_intializer, self.value)

        head, remaining = self.trunk.split_key_func(key)
        if head not in self.branches:
            retval = self.trunk.accumulator_intializer
        else:
            retval = self.branches[head][remaining]
        return self.trunk.accumulator_func(retval, self.value)

    def __delitem__(self, key):
        head, remaining = self.trunk.split_key_func(key)
        if not remaining and head in self.branches:
            del_size = self.branches[head].size
            self.size -= del_size
            del self.branches[head]
            return del_size
        if not remaining and head not in self.branches:
            return 0
        elif remaining:
            num_deleted = self.branches[head].__delitem__(remaining)
            self.size -= num_deleted
            return num_deleted

    def __contains__(self, key):
        if not key:
            return True

        head, remaining = self.trunk.split_key_func(key)
        if head not in self.branches:
            return False
        else:
            return self.branches[head][remaining]

    def __iter__(self):
        for key in self.branches:
            if self.is_set or self.branches[key].size == 1:
                yield self.trunk.join_key_func(key)
            for sub_result in self.branches[key]:
                yield self.trunk.join_key_func(key, sub_result)

    def __len__(self):
        return self.size
