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

import flawless.client
import flawless.client.decorators
import flawless.lib.config


# You can wrap a function using the flawless decorator and any exceptions that
# get thrown will be reported to the flawless backend & then re-raised
@flawless.client.decorators.wrap_function
def example1():
  raise Exception()



# You can also control behavior of the decorator. For instance you can set the
# number of times an error must occur before an email gets sent. You can also
# prevent the exception from being re-raised
@flawless.client.decorators.wrap_function(error_threshold=1, reraise_exception=False)
def example2():
  raise Exception()



# Finally, you can decorate an entire class. The class decorator wraps any instance
# method or classmethod in the class with the function decorator.
@flawless.client.decorators.wrap_class
class ExampleClass(object):

  def func1(self):
    raise Exception()

  @classmethod
  def func2(cls):
    raise Exception()



if __name__ == '__main__':
  # The client has three options to configure the flawless client
  # Option 1: Set flawless_hostport in the config file and call flawless.lib.config.init_config
  flawless.lib.config.init_config("../config/flawless.cfg")

  # Option 2: Call set_hostport
  flawless.client.set_hostport("localhost:9028")



  # example1 will re-raise the exception
  try:
    example1()
  except:
    pass

  # example 2 will not
  example2()

  # The class methods will re-raise the exception
  obj = ExampleClass()
  try:
    obj.func1()
  except:
    pass
