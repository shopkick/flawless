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

import copy
import time
import unittest


import flawless.client
import flawless.client.client
import flawless.client.decorators
from flawless.lib.data_structures.lru_cache import LRUCache
from flawless.server.stub import FlawlessServiceStub


@flawless.client.decorators.wrap_class
class ThriftTestHandler(object):

    def __init__(self):
        self.instancevar = 98

    def method(self, fail=False, result=42):
        return self._simulate_call(fail, result)

    @classmethod
    def classmeth(cls, fail=False, result=43):
        return cls._simulate_call(fail, result)

    @classmethod
    def _simulate_call(cls, fail=False, result=42):
        if fail:
            raise Exception()

        return result

    def check_health(self, fail=False, result=42, delay=0):
        return self._simulate_call(fail=fail, result=result, delay=delay)


class BaseErrorsTestCase(unittest.TestCase):

    def setUp(self):
        self.client_stub = FlawlessServiceStub()
        self.saved_get_get_service = flawless.client.client._get_service
        setattr(flawless.client.client, "_get_service",
                lambda: (self.client_stub, TransportStub(), flawless.client.client.HOSTPORT_INFO[0]))
        self.saved_config = copy.deepcopy(flawless.lib.config.get().__dict__)
        self.test_config = flawless.lib.config.get()
        self.test_config.__dict__ = dict((o.name, o.default) for o in flawless.lib.config.OPTIONS)
        flawless.client.set_hostports(["localhost:9028"])
        flawless.client.client.ERROR_CACHE = LRUCache(size=flawless.client.client.LRU_CACHE_SIZE)

    def tearDown(self):
        setattr(flawless.client.client, "_get_service", self.saved_get_get_service)
        flawless.lib.config.get().__dict__ = self.saved_config


class ClassDecoratorTestCase(BaseErrorsTestCase):
    def setUp(self):
        super(ClassDecoratorTestCase, self).setUp()
        self.handler = ThriftTestHandler()

    def test_returns_correct_result(self):
        self.assertEquals(56, self.handler.method(result=56))

    def test_returns_correct_result_for_classmethod(self):
        self.assertEquals(91, ThriftTestHandler.classmeth(result=91))

    def test_should_call_flawless_backend_on_exception(self):
        self.assertRaises(Exception, self.handler.method, fail=True)
        self.assertEquals(1, len(self.client_stub.record_error.args_list))
        errorFound = False
        req_obj = self.client_stub.record_error.last_args['request']
        for row in req_obj.traceback:
            if row.function_name == "_simulate_call":
                errorFound = True
            if row.function_name == "method":
                self.assertEquals('98', row.frame_locals['self.instancevar'])
        self.assertTrue(errorFound)
        self.assertEqual(None, req_obj.error_threshold)

    def test_logs_classvars(self):
        self.assertRaises(Exception, self.handler.method, fail=True)
        self.assertEquals(1, len(self.client_stub.record_error.args_list))
        errorFound = False
        req_obj = self.client_stub.record_error.last_args['request']
        for row in req_obj.traceback:
            if row.function_name == "_simulate_call":
                errorFound = True
        self.assertTrue(errorFound)
        self.assertEqual(None, req_obj.error_threshold)


class FunctionDecoratorTestCase(BaseErrorsTestCase):
    def setUp(self):
        super(FunctionDecoratorTestCase, self).setUp()
        flawless.client.client.SCRUBBED_VARIABLES_REGEX = None

    @flawless.client.decorators.wrap_function
    def example_func(self, fail=False, retval=None):
        myvar = 7
        if fail:
            raise Exception(":(")
        return retval

    @flawless.client.decorators.wrap_function(error_threshold=7, reraise_exception=False)
    def second_example_func(self, fail=False, retval=None):
        if fail:
            raise Exception("woohoo")
        return retval

    @flawless.client.decorators.wrap_function
    def scrubber_example_func(self, fail=False, retval=None):
        password = "banana"
        if fail:
            raise Exception(":(")
        return retval

    def test_returns_correct_result(self):
        self.assertEquals(7, self.example_func(fail=False, retval=7))

    def test_should_call_flawless_backend_on_exception(self):
        self.assertRaises(Exception, self.example_func, fail=True)
        errorFound = False
        req_obj = self.client_stub.record_error.last_args['request']
        for row in req_obj.traceback:
            if row.function_name == "example_func":
                errorFound = True
        self.assertTrue(errorFound)
        self.assertEqual(None, req_obj.error_threshold)
        self.assertEqual('exceptions.Exception', req_obj.exception_type)

    def test_does_not_call_flawless_if_backoff(self):
        flawless.client.client.HOSTPORT_INFO[0].backoff_ms = int(time.time() * 1000) + 1000
        self.assertRaises(Exception, self.example_func, fail=True)
        self.assertEqual(None, self.client_stub.record_error.last_args)
        flawless.client.client.HOSTPORT_INFO[0].backoff_ms = 0

    def test_does_not_call_flawless_if_error_is_being_cached(self):
        for i in range(flawless.client.client.CACHE_ERRORS_AFTER_N_OCCURRENCES * 2):
            self.assertRaises(Exception, self.example_func, fail=True)
        self.assertEquals(len(self.client_stub.record_error.args_list),
                          flawless.client.client.CACHE_ERRORS_AFTER_N_OCCURRENCES + 1)
        self.assertEquals(self.client_stub.record_error.last_args['request'].error_count, 6)

    def test_decorator_with_kwargs(self):
        self.second_example_func(fail=True)
        errorFound = False
        req_obj = self.client_stub.record_error.last_args['request']
        for row in req_obj.traceback:
            if row.function_name == "second_example_func":
                errorFound = True
        self.assertTrue(errorFound)
        self.assertEqual(7, req_obj.error_threshold)

    def test_logs_locals(self):
        self.assertRaises(Exception, self.example_func, fail=True)
        errorFound = False
        req_obj = self.client_stub.record_error.last_args['request']
        for row in req_obj.traceback:
            if row.function_name == "example_func":
                errorFound = True
                self.assertEquals('7', row.frame_locals['myvar'])
        self.assertTrue(errorFound)
        self.assertEqual(None, req_obj.error_threshold)

    def test_scrubbing(self):
        flawless.client.client.install_scrubbers("password")
        self.assertRaises(Exception, self.scrubber_example_func, fail=True)
        errorFound = False
        req_obj = self.client_stub.record_error.last_args['request']
        for row in req_obj.traceback:
            if row.function_name == "scrubber_example_func":
                errorFound = True
                self.assertEquals('**scrubbed**', row.frame_locals['password'])
        self.assertTrue(errorFound)
        self.assertEqual(None, req_obj.error_threshold)


class FuncThreadStub(object):
    def __init__(self, target):
        self.target = target

    def start(self):
        self.target()


class TransportStub(object):
    def open(self):
        pass

    def close(self):
        pass

    def isOpen(self):
        return True


if __name__ == '__main__':
    unittest.main()
