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

import functools
import traceback
import linecache
import os.path
import socket
import sys
import warnings

from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.protocol import TBinaryProtocol

import flawless.client.default
import flawless.lib.config
import flawless.server.api.ttypes as api_ttypes
from flawless.server.api import Flawless


config = flawless.lib.config.get()

MAX_VARIABLE_REPR = 250
MAX_LOCALS = 100
NUM_FRAMES_TO_SAVE = 20


def _get_backend_host():
    return config.flawless_hostport or flawless.client.default.hostport


def _get_service():
    hostport = _get_backend_host()
    if not hostport:
        warnings.warn("Unable to record error: flawless server hostport not set", RuntimeWarning)
        return None, None

    host, port = hostport.split(":")
    tsocket = TSocket.TSocket(host, int(port))
    tsocket.setTimeout(2000)  # 2 second timeout
    transport = TTransport.TFramedTransport(tsocket)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    client = Flawless.Client(protocol)
    transport.open()
    return client, transport


def _myrepr(s):
    try:
        repr_str = repr(s)
        return repr_str[:MAX_VARIABLE_REPR] + "..." * int(len(repr_str) > MAX_VARIABLE_REPR)
    except:
        return "Could not except repr for this field"


def set_hostport(hostport):
    flawless.client.default.hostport = hostport


def record_error(hostname, sys_traceback, exception_message, preceding_stack=None,
                 error_threshold=None, additional_info=None):
    ''' Helper function to record errors to the flawless backend '''
    try:
        stack = []
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
                frame_locals = dict((k, _myrepr(v)) for k, v in
                                    tb.tb_frame.f_locals.items()[:MAX_LOCALS] if k != "self")
                if "self" in tb.tb_frame.f_locals and hasattr(tb.tb_frame.f_locals["self"], "__dict__"):
                    frame_locals.update(dict(("self." + k, _myrepr(v)) for k, v in
                                             tb.tb_frame.f_locals["self"].__dict__.items()[:MAX_LOCALS]
                                             if k != "self"))

            # TODO (john): May need to prepend site-packages to filename to get correct path
            stack_lines.append(
                api_ttypes.StackLine(filename=os.path.abspath(filename), line_number=lineno,
                                     function_name=func_name, text=line, frame_locals=frame_locals)
            )

        req = api_ttypes.RecordErrorRequest(
            traceback=stack_lines,
            exception_message=exception_message,
            hostname=hostname,
            error_threshold=error_threshold,
            additional_info=additional_info,
        )

        client, transport = _get_service()
        if client and transport:
            client.record_error(req)
            transport.close()
    except:
        raise


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
                sys_traceback=sys_traceback,
                preceding_stack=preceding_stack,
                exception_message=repr(value),
                error_threshold=error_threshold,
            )

            # Reraise exception if so desired
            if reraise_exception:
                setattr(value, "_flawless_already_caught", True)
                raise value, None, sys_traceback
    return wrapped_func_with_error_reporting
