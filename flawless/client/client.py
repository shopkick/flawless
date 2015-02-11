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

import functools
import hashlib
import linecache
import math
import os.path
import random
import re
import socket
import sys
import time
import traceback
import warnings

from thrift.Thrift import TException
from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.protocol import TBinaryProtocol

import flawless.lib.config
from flawless.lib.data_structures.lru_cache import LRUCache
import flawless.server.api.ttypes as api_ttypes
from flawless.server.api import Flawless


config = flawless.lib.config.get()

MAX_VARIABLE_REPR = 250
MAX_LOCALS = 100
NUM_FRAMES_TO_SAVE = 20

HOSTPORT_INFO = list()
SCRUBBED_VARIABLES_REGEX = None

CACHE_ERRORS_AFTER_N_OCCURRENCES = 10
REPORT_AFTER_N_MILLIS = 10 * 60 * 1000  # 10 minutes
LRU_CACHE_SIZE = 200
ERROR_CACHE = LRUCache(size=LRU_CACHE_SIZE)


class HostportInfo(object):

    def __init__(self, hostport):
        host, port = hostport.split(":")
        self.host = host
        self.port = int(port)
        self.backoff_ms = 0
        self.consecutive_connection_errors = 0

    def increment_backoff(self):
        self.consecutive_connection_errors = max(12, self.consecutive_connection_errors + 1)
        backoff = 1000 * random.randint(1, 2 ** self.consecutive_connection_errors)
        self.backoff_ms = _get_epoch_ms() + backoff

    def decrement_backoff(self):
        self.consecutive_connection_errors = int(self.consecutive_connection_errors / 2)
        if self.consecutive_connection_errors > 0:
            backoff = 1000 * random.randint(1, 2 ** self.consecutive_connection_errors)
            self.backoff_ms = _get_epoch_ms() + backoff


class CachedErrorInfo(object):

    def __init__(self):
        self.last_report_ts = _get_epoch_ms()
        self.last_occur_ts = _get_epoch_ms()
        self.curr_count = 0
        self.last_report_count = 0

    @classmethod
    def get_hash_key(cls, stack_lines):
        m = hashlib.md5()
        for line in stack_lines:
            m.update(line.filename)
            m.update(str(line.line_number))
        return m.digest()

    def increment(self):
        self.last_occur_ts = _get_epoch_ms()
        self.curr_count += 1

    def mark_reported(self):
        self.last_report_ts = _get_epoch_ms()
        diff = self.curr_count - self.last_report_count
        self.last_report_count = self.curr_count
        return diff

    def should_report(self):
        report_conditions = list()
        report_conditions.append(self.curr_count <= CACHE_ERRORS_AFTER_N_OCCURRENCES)
        report_conditions.append(self.last_report_ts < (_get_epoch_ms() - REPORT_AFTER_N_MILLIS))
        log_count = math.log(self.curr_count, 2)
        report_conditions.append(int(log_count) == log_count)
        return any(report_conditions)


def _get_epoch_ms():
    return int(time.time() * 1000)


def set_hostports(hostports):
    if type(hostports) not in [tuple, list]:
        raise ValueError("hostports must be a list or tuple")
    global HOSTPORT_INFO
    HOSTPORT_INFO = [HostportInfo(hp) for hp in hostports]


def install_scrubbers(variables_regex):
    global SCRUBBED_VARIABLES_REGEX
    SCRUBBED_VARIABLES_REGEX = re.compile(variables_regex)


def _get_backend_host():
    if config.flawless_hostports and not HOSTPORT_INFO:
        set_hostports(config.flawless_hostports)
    return random.choice(HOSTPORT_INFO) if HOSTPORT_INFO else None


def _get_service():
    hostport_info = _get_backend_host()
    if not hostport_info:
        warnings.warn("Unable to record error: flawless server hostport not set", RuntimeWarning)
        return None, None, None

    tsocket = TSocket.TSocket(hostport_info.host, hostport_info.port)
    tsocket.setTimeout(2000)  # 2 second timeout
    transport = TTransport.TFramedTransport(tsocket)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    client = Flawless.Client(protocol)
    return client, transport, hostport_info


def _send_request(req):
    # Try to send the request. If there are too many connection errors, then backoff
    client, transport, hostport_info = _get_service()
    try:
        if all([client, transport, hostport_info]) and _get_epoch_ms() >= hostport_info.backoff_ms:
            transport.open()
            client.record_error(req)
            hostport_info.decrement_backoff()
    except TException:
        hostport_info.increment_backoff()
        raise
    finally:
        if transport and transport.isOpen():
            transport.close()


def _myrepr(var_name, value):
    try:
        if SCRUBBED_VARIABLES_REGEX and SCRUBBED_VARIABLES_REGEX.match(var_name):
            return '**scrubbed**'

        repr_str = repr(value)
        return repr_str[:MAX_VARIABLE_REPR] + "..." * int(len(repr_str) > MAX_VARIABLE_REPR)
    except:
        return "Exception executing repr for this field"


def record_error(hostname, exc_info, preceding_stack=None, error_threshold=None, additional_info=None):
    ''' Helper function to record errors to the flawless backend '''
    stack = []
    exc_type, exc_value, sys_traceback = exc_info

    while sys_traceback is not None:
        stack.append(sys_traceback)
        sys_traceback = sys_traceback.tb_next

    stack_lines = []
    for row in preceding_stack or []:
        stack_lines.append(
            api_ttypes.StackLine(filename=os.path.abspath(row[0]), line_number=row[1],
                                 function_name=row[2], text=row[3])
        )

    for index, tb in enumerate(stack):
        filename = tb.tb_frame.f_code.co_filename
        func_name = tb.tb_frame.f_code.co_name
        lineno = tb.tb_lineno
        line = linecache.getline(filename, lineno, tb.tb_frame.f_globals)
        frame_locals = None
        if index >= (len(stack) - NUM_FRAMES_TO_SAVE):
            # Include some limits on max string length & number of variables to keep things from getting
            # out of hand
            frame_locals = dict((k, _myrepr(k, v)) for k, v in
                                tb.tb_frame.f_locals.items()[:MAX_LOCALS] if k != "self")
            if "self" in tb.tb_frame.f_locals and hasattr(tb.tb_frame.f_locals["self"], "__dict__"):
                frame_locals.update(dict(("self." + k, _myrepr(k, v)) for k, v in
                                         tb.tb_frame.f_locals["self"].__dict__.items()[:MAX_LOCALS]
                                         if k != "self"))

        stack_lines.append(
            api_ttypes.StackLine(filename=os.path.abspath(filename), line_number=lineno,
                                 function_name=func_name, text=line, frame_locals=frame_locals)
        )

    # Check LRU cache & potentially do not send error report if this client has already reported this error
    # several times.
    key = CachedErrorInfo.get_hash_key(stack_lines)
    info = ERROR_CACHE.get(key) or CachedErrorInfo()
    info.increment()
    ERROR_CACHE[key] = info
    if info.should_report():
        error_count = info.mark_reported()
        _send_request(
            api_ttypes.RecordErrorRequest(
                traceback=stack_lines,
                exception_message=repr(exc_value),
                exception_type=exc_type.__module__ + "." + exc_type.__name__,
                hostname=hostname,
                error_threshold=error_threshold,
                additional_info=additional_info,
                error_count=error_count,
            )
        )


def _safe_wrap(func):
    safe_attrs = [attr for attr in functools.WRAPPER_ASSIGNMENTS if hasattr(func, attr)]
    return functools.wraps(func, safe_attrs)


def _wrap_function_with_error_decorator(func,
                                        save_current_stack_trace=True,
                                        reraise_exception=True,
                                        error_threshold=None):
    preceding_stack = []
    if save_current_stack_trace:
        preceding_stack = traceback.extract_stack()

    @_safe_wrap(func)
    def wrapped_func_with_error_reporting(*args, **kwargs):
        if not _get_backend_host():
            warnings.warn("flawless server hostport not set", RuntimeWarning, stacklevel=2)
        try:
            return func(*args, **kwargs)
        except:
            type, value, sys_traceback = sys.exc_info()

            # Check to try and prevent multiple reports of the same exception
            if hasattr(value, "_flawless_already_caught"):
                if reraise_exception:
                    raise value, None, sys_traceback
                else:
                    return

            # Get trackback & report it
            hostname = socket.gethostname()
            record_error(
                hostname=hostname,
                exc_info=(type, value, sys_traceback),
                preceding_stack=preceding_stack,
                error_threshold=error_threshold,
            )

            # Reraise exception if so desired
            if reraise_exception:
                setattr(value, "_flawless_already_caught", True)
                raise value, None, sys_traceback
    return wrapped_func_with_error_reporting
