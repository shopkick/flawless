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
import os.path
import re
from setuptools import setup, find_packages

def markdown_to_reST(text):
  '''This is not a general purpose converter. Only converts this readme'''
  # Convert parameters to italics and prepend a newline
  text = re.sub(pattern=r"\n       (\w+) - (.+)\n",
                repl=r"\n\n       *\g<1>* - \g<2>\n",
                string=text)

  # Parse [http://url](text), and just leave the url
  text = re.sub(pattern=r"\[([^\]]+)\]\([^)]+\)",
                repl=r"\g<1>",
                string=text)

  # Disable formatting of numbered lists
  text = re.sub(pattern=r"\n(\d+). ",
                repl=r"\n\\\g<1>. ",
                string=text)
  return text

setup(
  name='flawless',
  version='0.3.5',
  description='Python Error Monitoring and Reporting',
  long_description=markdown_to_reST(open("README.md").read()),
  license='MPL 2.0',
  author='John Egan',
  author_email='jwegan@gmail.com',
  url='http://github.com/shopkick/flawless',
  zip_safe=False,
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

