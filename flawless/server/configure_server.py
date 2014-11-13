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

import ConfigParser
import os
import os.path
import subprocess
import socket
import shutil

import flawless.lib.config
from flawless.lib.version_control import repo


def interview(conf_path):
    options = dict(
        log_level="WARNING",
        port="9028",
    )

    print "Configure server host & port"
    print "----------------------------"
    options["port"] = raw_input("What port should the server listen on (suggested: 9028): ")
    options["hostname"] = raw_input("Internet browser accessible hostname to access this server "
                                    "(ex: http://%s): " % socket.gethostname())

    print "\nConfigure Email"
    print "---------------"
    options["smtp_host"] = raw_input("What is host:port for your smtp server (ex: smtphost:25): ").strip()
    smtp_user = raw_input("What is the username should flawless use to access your smtp "
                          "server (leave blank if username not required)? ").strip()
    if smtp_user:
        options["smtp_user"] = smtp_user
        options["smtp_password"] = raw_input("What is %s's password? " % smtp_user).strip()
    options["email_domain_name"] = raw_input("What is your email domain (ex: example.com): ").strip()
    options["ignore_vcs_email_domain"] = raw_input("Are all developer emails on %s (y/n): " %
                                                   options["email_domain_name"])[0] in ['y', 'Y']
    options["default_contact"] = raw_input("If Flawless can't figure out which developer to email, "
                                           "what should be the default email address that Flawless "
                                           "sends to? ").strip()

    print "\nConfigure Directory Paths"
    print "-------------------------"
    conf_dir_path = os.path.dirname(conf_path)
    if (raw_input("Use %s as the directory to store configuration information (y/n)? " % conf_dir_path).strip()[0]
            in ['n', 'N']):
        conf_dir_path = raw_input("Enter desired configuration directory path: ").strip()
        if not os.path.exists(conf_dir_path):
            os.makedirs(conf_dir_path)
            copy_files = True
        else:
            copy_files = raw_input("Overwrite existing files in %s (y/n)? " % conf_dir_path).strip()[0] in ['y', 'Y']

        if copy_files:
            default_dir = os.path.dirname(flawless.lib.config.default_path)
            files_to_copy = [f for f in os.listdir(default_dir)
                             if not f.startswith('.')]
            for filename in files_to_copy:
                shutil.copy2(os.path.join(default_dir, filename), conf_dir_path)
    options["data_dir_path"] = raw_input("Enter path to directory were Flawless can persist "
                                         "error data to disk (ex: /tmp/flawless/): ").strip()

    print "\nConfigure Repository Access"
    print "---------------------------"

    if subprocess.call(["which", "git"], stdout=open(os.devnull)):
        print "Could not detect git. Please enter path to git executable"
        git_cli_path = raw_input("path to git binary: ")
        options["git_cli_path"] = git_cli_path

    print "Flawless needs access to a regularly updated copy of your repo in order to run git-blame"
    print "and determine which developer caused an error. Flawless can either checkout"
    print "and manage the repo iteself, or you can just provide the directory path to"
    print "the repo and mange keeping the repo up to date yourself\n"
    repo_url = repo_dir = branch_pattern = None
    if raw_input("Should Flawless checkout a copy of your repo (y/n): ")[0] in ['y', 'Y']:
        print "Please enter the URI for the repo, including username & password if necessary"
        print "Examples: https://username:password@example.com/path/repo.git or"
        print "git://username@example.com/repo.git"
        repo_url = raw_input("Git remote URI: ").strip()
        repo_dir = raw_input("Where should the repo live (ex: /tmp/flawless_repo): ").strip()

        if raw_input("Do you cut release branches for the code flawless will monitor (y/n)? ")[0] in ['y', 'Y']:
            print "Flawless will regularly check for new branches and always work off the latest branch"
            print "Latest branch is determined by sorting branch names by name"
            print "Please enter a Python regular expression that identifies your release branch names"
            print "Example: example-server-release"
            branch_pattern = raw_input("regexp: ").strip()
    else:
        repo_dir = raw_input("What is the filepath to your git repo (ex: /tmp/repo): ").strip()

    options["repo_dir"] = repo_dir
    options["repo_url"] = repo_url
    options["repo_branch_pattern"] = branch_pattern
    options["repo_type"] = "git"

    print "\nBasic configuration done"
    if raw_input("Overwrite flawless.cfg (y/n)? ")[0] in ['y', 'Y']:
        parser = ConfigParser.SafeConfigParser()
        config_path = os.path.join(conf_dir_path, "flawless.cfg")
        parser.read(config_path)
        if not parser.has_section("flawless"):
            parser.add_section("flawless")
        for option, value in options.items():
            if value is not None:
                parser.set("flawless", str(option), str(value))
        with open(config_path, "w") as fh:
            parser.write(fh)

    if repo_url:
        print "\nYou elected to have flawless manage a copy of your git repo. Flawless will now attempt to"
        print "clone your repo"
        new_repo = repo.GitRepository(local_path=repo_dir,
                                      remote_url=repo_url,
                                      branch_pattern=branch_pattern)
        new_repo.create()

    print "\n\nSetup complete!"
    print "Start the server by running:"
    print "flawless start -conf %s" % os.path.join(conf_dir_path, "flawless.cfg")
    print ("Check server is running by visiting http://%s:%s/check_health" %
           (options["hostname"], options["port"]))


if __name__ == '__main__':
    interview(flawless.lib.config.default_path)
