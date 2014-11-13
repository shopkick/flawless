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

import sys

import flawless.lib.config
import flawless.server.server
import flawless.server.configure_server


def show_options():
    for option in flawless.lib.config.OPTIONS:
        print option.name
        print "    default value: %s" % repr(option.default)
        print "    type: %s" % str(option.type)
        print "    description: %s\n" % option.description


def usage():
    print "Usage: flawless [start|configure|options|help] [-conf path]"
    print "    Commands:"
    print "        start - Start the server"
    print "        configure - Run server setup script"
    print "        options - Display list of server configuration options for flawless.cfg"
    print "        help - Display this description"
    print "    Options:"
    print "        -conf path: Path to flawless.cfg"


def main():
    conf_path = flawless.lib.config.default_path

    command = None if len(sys.argv) > 1 else usage
    args_list = list(reversed(sys.argv[1:]))
    while args_list:
        arg = args_list.pop()
        if arg == "start" and not command:
            command = lambda: flawless.server.server.serve(conf_path)
        elif arg == "configure" and not command:
            command = lambda: flawless.server.configure_server.interview(conf_path)
        elif arg == "options" and not command:
            command = show_options
        elif arg == "help" and not command:
            command = usage
        elif arg == "-conf":
            if not args_list:
                command = usage
                break
            conf_path = args_list.pop()
        else:
            command = usage
            break

    command()


if __name__ == '__main__':
    main()
