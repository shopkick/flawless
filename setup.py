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

import os
import os.path
from setuptools import setup, find_packages

setup(
  name='flawless',
  version='0.1',
  description='Python Error Monitoring and Reporting',
  long_description=open("README").read(),
  license='MPL 2.0',
  author='John Egan',
  author_email='john@shopkick.com',
  url='http://github.com/shopkick/flawless',
  packages=find_packages(exclude=['ez_setup', 'examples', 'packages', 'tests*']),
  data_files=[('config', [os.path.join('config', f) for f in os.listdir('config')
                          if not f.startswith('.')])],
  entry_points="""
  [console_scripts]
  flawless = flawless.server.manage:main
  """,
  classifiers=[
    "Development Status :: 3 - Alpha",
    "Framework :: Pylons",
    "Framework :: Django",
    "Framework :: Pyramid",
    "Framework :: Paste",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    "Topic :: Software Development :: Bug Tracking",
    "Topic :: Software Development :: Quality Assurance",
  ],
)

