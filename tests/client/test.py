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
# Author: John Egan <john@shopkick.com>

import copy
import unittest


import flawless.client
import flawless.client.decorators
import flawless.server.api as api



@flawless.client.decorators.wrap_class
class ThriftTestHandler(object):
  def __init__(self):
    self.classvar = 99

  def method(self, fail=False, result=42):
    return self._simulate_call(fail, result)

  def _simulate_call(self, fail=False, result=42):
    if fail:
      raise Exception()

    return result

  def check_health(self, fail=False, result=42, delay=0):
    return self._simulate_call(fail=fail, result=result, delay=delay)


class BaseErrorsTestCase(unittest.TestCase):

  def setUp(self):
    self.saved_send_func = flawless.client._send_request
    setattr(flawless.client, "_send_request", self._send_request_stub_func)
    self.saved_config = copy.deepcopy(flawless.lib.config.get().__dict__)
    self.test_config = flawless.lib.config.get()
    self.test_config.__dict__ = dict((o.name, o.default) for o in flawless.lib.config.OPTIONS)
    flawless.client.set_hostport("localhost")
    self.last_req = None
    self.req_list = []

  def tearDown(self):
    setattr(flawless.client, "_send_request", self.saved_send_func)
    flawless.lib.config.get().__dict__ = self.saved_config

  def _send_request_stub_func(self, req):
    self.last_req = req
    self.req_list.append(req)


class ClassDecoratorTestCase(BaseErrorsTestCase):
  def setUp(self):
    super(ClassDecoratorTestCase, self).setUp()
    self.handler = ThriftTestHandler()

  def test_returns_correct_result(self):
    self.assertEquals(56, self.handler.method(result=56))

  def test_should_call_flawless_backend_on_exception(self):
    self.assertRaises(Exception, self.handler.method, fail=True)
    self.assertEquals(1, len(self.req_list))
    errorFound = False
    req_obj = api.RecordErrorRequest.loads(self.last_req.get_data())
    for row in req_obj.traceback:
      if row.function_name == "_simulate_call":
        errorFound = True
    self.assertTrue(errorFound)
    self.assertEqual(None, req_obj.error_threshold)

  def test_logs_classvars(self):
    self.assertRaises(Exception, self.handler.method, fail=True)
    self.assertEquals(1, len(self.req_list))
    errorFound = False
    req_obj = api.RecordErrorRequest.loads(self.last_req.get_data())
    for row in req_obj.traceback:
      if row.function_name == "_simulate_call":
        errorFound = True
        self.assertEquals('99', row.frame_locals['self.classvar'])
    self.assertTrue(errorFound)
    self.assertEqual(None, req_obj.error_threshold)


class FunctionDecoratorTestCase(BaseErrorsTestCase):
  def setUp(self):
    super(FunctionDecoratorTestCase, self).setUp()

  @flawless.client.decorators.wrap_function
  def example_func(self, fail=False, retval=None):
    myvar = 7
    if fail:
      raise Exception(":(")
    return  retval

  @flawless.client.decorators.wrap_function(error_threshold=7, reraise_exception=False)
  def second_example_func(self, fail=False, retval=None):
    if fail:
      raise Exception("woohoo")
    return  retval

  def test_returns_correct_result(self):
    self.assertEquals(7, self.example_func(fail=False, retval=7))

  def test_should_call_flawless_backend_on_exception(self):
    self.assertRaises(Exception, self.example_func, fail=True)
    errorFound = False
    req_obj = api.RecordErrorRequest.loads(self.last_req.get_data())
    for row in req_obj.traceback:
      if row.function_name == "example_func":
        errorFound = True
    self.assertTrue(errorFound)
    self.assertEqual(None, req_obj.error_threshold)

  def test_decorator_with_kwargs(self):
    self.second_example_func(fail=True)
    errorFound = False
    req_obj = api.RecordErrorRequest.loads(self.last_req.get_data())
    for row in req_obj.traceback:
      if row.function_name == "second_example_func":
        errorFound = True
    self.assertTrue(errorFound)
    self.assertEqual(7, req_obj.error_threshold)

  def test_logs_locals(self):
    self.assertRaises(Exception, self.example_func, fail=True)
    errorFound = False
    req_obj = api.RecordErrorRequest.loads(self.last_req.get_data())
    for row in req_obj.traceback:
      if row.function_name == "example_func":
        errorFound = True
        self.assertEquals('7', row.frame_locals['myvar'])
    self.assertTrue(errorFound)
    self.assertEqual(None, req_obj.error_threshold)


class FuncThreadStub(object):
  def __init__(self, target):
    self.target = target

  def start(self):
    self.target()


if __name__ == '__main__':
  unittest.main()

