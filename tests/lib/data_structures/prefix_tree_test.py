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

import unittest

from flawless.lib.data_structures import prefix_tree

class PrefixTreeTestCase(unittest.TestCase):

  def setUp(self):
    super(PrefixTreeTestCase, self).setUp()

  def _flatten_branch(self, key, tree):
    head, tail = None, key
    node_chain = [tree.root]
    cur_node = tree.root
    while tail:
      head, tail = tree.split_key_func(tail)
      self.assertTrue(head in cur_node.branches)
      node_chain.append(cur_node.branches[head])
      cur_node = cur_node.branches[head]
    return node_chain

  def test_setting_value(self):
    tree = prefix_tree.StringPrefixTree()
    tree["abcd"] = 7
    expected_keys = ['a', 'b', 'c', 'd']
    node_chain = self._flatten_branch("abcd", tree)
    self.assertEquals(5, len(node_chain))
    for node in node_chain[1:-1]:
      self.assertEquals(node.value, None)
      self.assertEquals(node.is_set, False)
      self.assertEquals(1, node.size)

    self.assertEquals(True, node_chain[4].is_set)
    self.assertEquals(7, node_chain[4].value)
    self.assertEquals(1, node_chain[4].size)

  def test_getting_value(self):
    tree = prefix_tree.StringPrefixTree()
    tree["abcd"] = 7
    self.assertEquals(7, tree["abcd"])

  def test_len(self):
    tree = prefix_tree.StringPrefixTree()
    tree["abcd"] = 4
    tree["ab"] = 2
    node_chain = self._flatten_branch("abcd", tree)
    self.assertEquals(5, len(node_chain))
    self.assertEquals(2, len(tree))
    for index, node in enumerate(node_chain):
      if index in [2,4]:
        self.assertEquals(True, node.is_set)
        self.assertEquals(index, node.value)
      else:
        self.assertEquals(False, node.is_set)
        self.assertEquals(None, node.value)
      self.assertEquals(2 if index <= 2 else 1, node.size)

if __name__ == '__main__':
  unittest.main()
