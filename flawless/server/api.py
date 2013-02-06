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

import pickle


class ApiObject(object):
  _api_attributes = []

  def __init__(self, *args, **kwargs):
    values = dict((k, None) for k, _ in self._api_attributes)
    values.update(zip([k for k, _ in self._api_attributes], args))
    values.update(kwargs)
    primitives = [int, str, bool, unicode, float, list, dict, set]
    values = dict((k, t(values[k]) if values[k] and t in primitives else values[k])
                  for k, t in self._api_attributes)
    self.__dict__.update(values)

  def dumps(self):
    return pickle.dumps(self, pickle.HIGHEST_PROTOCOL)

  @staticmethod
  def loads(strval):
    return pickle.loads(strval)

  def __hash__(self):
    return reduce(lambda x, y: x ^ hash(y), self.__dict__.iteritems(), 1)

  def __str__(self):
    return repr(self)

  def __repr__(self):
    return "%s(%s)" % (
        self.__class__.__name__,
        ", ".join("%s=%s" % (k,repr(v)) for k,v in self.__dict__.items())
    )

  def __eq__(self, other):
    return type(self) == type(other) and self.__dict__ == other.__dict__


class ErrorKey(ApiObject):
  _api_attributes = [
    ('filename', str),
    ('line_number', int),
    ('function_name', str),
    ('text', str),
  ]


class StackLine(ApiObject):
  _api_attributes = [
    ('filename', str),
    ('line_number', int),
    ('function_name', str),
    ('text', str),
  ]


class RecordErrorRequest(ApiObject):
  _api_attributes = [
    ('traceback', list),
    ('exception_message', str),
    ('hostname', str),
    ('error_threshold', int),
    ('additional_info', str),
  ]


class ErrorInfo(ApiObject):
  _api_attributes = [
    ('error_count', int),
    ('developer_email', str),
    ('date', str),
    ('email_sent', bool),
    ('last_occurrence', str),
    ('is_known_error', bool),
    ('last_error_data', RecordErrorRequest),
  ]
