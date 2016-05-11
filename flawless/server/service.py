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

from __future__ import absolute_import
import __main__

import cgi
import copy
import email
import collections
import datetime
import inspect
import logging
import os
import os.path
import re
import smtplib
import subprocess
import sys
import threading
import time
import traceback
import urllib
import urlparse

from thrift.Thrift import TType

import flawless.lib.config
from flawless.lib.data_structures import prefix_tree
from flawless.lib.storage import DiskStorage
from flawless.lib.version_control.repo import get_repository
import flawless.server.api.ttypes as api_ttypes

try:
    import pprint
except:
    pprint = None


log = logging.getLogger(__name__)
config = flawless.lib.config.get()


############################## EXTEND THRIFT TTYPES ##############################

def code_identifier_equality(self, other):
    # We allow people to whitelist entire files, or functions by setting function_name to None or
    # code-fragment to None
    if self.filename != other.filename:
        return False
    if self.function_name and other.function_name and self.function_name != other.function_name:
        return False

    # Compress whitespace characters to make the comparissions more forgiving
    self_fragment = None if not self.code_fragment else re.sub("\s+", " ", self.code_fragment.strip())
    other_fragment = None if not other.code_fragment else re.sub("\s+", " ", other.code_fragment.strip())
    if (self_fragment and other_fragment and self_fragment not in other_fragment and
            other_fragment not in self_fragment):
        return False

    return True

api_ttypes.CodeIdentifier.__eq__ = code_identifier_equality
api_ttypes.KnownError.__eq__ = code_identifier_equality
api_ttypes.ErrorKey.__hash__ = lambda self: reduce(lambda x, y: x ^ hash(y), self.__dict__.iteritems(), 1)


############################## BASE SERVICE CLASS ##############################

class FlawlessServiceBaseClass(object):
    """Contains numerous shared helper functions for the ThriftService & WebService classes"""

    def __init__(self,
                 storage_factory=DiskStorage,
                 thread_cls=threading.Thread,
                 open_process_func=subprocess.Popen,
                 smtp_client_cls=smtplib.SMTP,
                 time_func=time.time):
        self.__dict__.update({k: v for k, v in locals().iteritems() if k != 'self'})
        self.extract_base_path_patterns = [re.compile('^.*/%s/?(.*)$' % d) for d in
                                           config.report_runtime_package_directory_names]
        self.raise_exception_pattern = re.compile('^\s*raise[ \n]')
        self.only_blame_patterns = [re.compile(p) for p in config.only_blame_filepaths_matching]
        self._read_whitelist_configs()

    ############################## Parse Config Files ##############################

    def _read_whitelist_configs(self):
        config_storage = self.storage_factory(partition=None)
        config_storage.open()

        # Whitelists
        self.building_blocks = self._parse_whitelist(config_storage["building_blocks"] or
                                                     api_ttypes.CodeIdentifierList())
        self.third_party_whitelist = self._parse_whitelist(config_storage["third_party_whitelist"] or
                                                           api_ttypes.CodeIdentifierList())
        self.known_errors = self._parse_whitelist(config_storage["known_errors"] or
                                                  api_ttypes.KnownErrorList())
        self.ignored_exceptions = set((config_storage["ignored_exceptions"] or
                                       api_ttypes.IgnoredExceptionList()).exceptions)

        # Watchers
        self.watch_all_errors, self.watch_only_if_blamed = self._parse_watchers_file(config_storage["watch_list"] or
                                                                                     api_ttypes.WatchList())
        self.disownerships = self._parse_disownership(config_storage["disownership_list"] or
                                                      api_ttypes.FileDisownershipList())

        # Email remapping
        self.email_remapping = config_storage["email_remapping"] or api_ttypes.EmailRemapping()

        config_storage.close()

    def _parse_whitelist(self, code_identifier_list):
        parsed_objs = collections.defaultdict(list)
        for item in code_identifier_list.identifiers:
            parsed_objs[item.filename].append(item)
        return parsed_objs

    def _parse_watchers_file(self, watch_list):
        all_error_tree = prefix_tree.FilePathTree()
        blame_only_tree = prefix_tree.FilePathTree()

        for watch in watch_list.watches:
            tree = all_error_tree if watch.watch_all_errors else blame_only_tree
            if watch.filepath not in tree:
                tree[watch.filepath] = list()
            tree[watch.filepath].append(watch.email)

        # Set all_error_tree to have accumulator that will allow us to find everyone who was watching
        # the file or a parent of the file
        all_error_tree.set_accumulator(
            accumulator_intializer=list(),
            accumulator_func=lambda x, y: x + y if y else x,
        )

        return all_error_tree, blame_only_tree

    def _parse_disownership(self, disownership_list):
        disownership_tree = prefix_tree.FilePathTree()
        for entry in disownership_list.disownerships:
            if entry.filepath not in disownership_tree:
                disownership_tree[entry.filepath] = list()
            disownership_tree[entry.filepath].append(entry)

        # Set disownership_tree to have accumulator that will allow us to find everyone who has disowned
        # the file or a parent of the file
        disownership_tree.set_accumulator(
            accumulator_intializer=list(),
            accumulator_func=lambda x, y: x + y if y else x,
        )
        return disownership_tree


    ############################## Timestamp Helpers ##############################

    def _partition_for_ms(self, epoch_ms):
        timestamp_date = self._convert_epoch_ms(cls=datetime.date, epoch_ms=epoch_ms)
        timestamp_date = timestamp_date - datetime.timedelta(days=timestamp_date.isoweekday() % 7)
        file_path = os.path.join(config.data_dir_path, "flawless-errors-" + timestamp_date.strftime("%Y-%m-%d"))
        return file_path

    def _epoch_ms(self):
        return int(self.time_func() * 1000)

    def _convert_epoch_ms(self, cls, epoch_ms=None):
        if not epoch_ms:
            epoch_ms = self._epoch_ms()
        return cls.fromtimestamp(epoch_ms / 1000.)

    ############################## Traceback/Line Type Helpers ##############################

    def _blame_line(self, traceback):
        '''Figures out which line in traceback is to blame for the error.
        Returns a 3-tuple of (ErrorKey, StackTraceEntry, [email recipients])'''
        key = None
        blamed_entry = None
        email_recipients = []
        for stack_line in traceback:
            line_type = self._get_line_type(stack_line)
            if line_type == api_ttypes.LineType.THIRDPARTY_WHITELIST:
                return None, None, None, True
            elif line_type in [api_ttypes.LineType.DEFAULT, api_ttypes.LineType.KNOWN_ERROR]:
                filepath = self._get_basepath(stack_line.filename)
                entry = api_ttypes.CodeIdentifier(filepath, stack_line.function_name, stack_line.text)
                blamed_entry = entry
                key = api_ttypes.ErrorKey(filepath, stack_line.line_number, stack_line.function_name, stack_line.text)
                if filepath in self.watch_all_errors:
                    email_recipients.extend(self.watch_all_errors[filepath])
        return (key, blamed_entry, email_recipients, False)

    def _get_line_type(self, line):
        filepath = self._get_basepath(line.filename)
        if not filepath:
            return api_ttypes.LineType.BAD_FILEPATH

        entry = api_ttypes.CodeIdentifier(filepath, line.function_name, line.text)
        if entry in self.third_party_whitelist[filepath]:
            return api_ttypes.LineType.THIRDPARTY_WHITELIST
        elif not self._matches_filepath_pattern(filepath):
            return api_ttypes.LineType.IGNORED_FILEPATH
        elif entry in self.building_blocks[filepath]:
            return api_ttypes.LineType.BUILDING_BLOCK
        elif entry in self.known_errors[filepath]:
            return api_ttypes.LineType.KNOWN_ERROR
        elif self.raise_exception_pattern.match(line.text):
            return api_ttypes.LineType.RAISED_EXCEPTION
        else:
            return api_ttypes.LineType.DEFAULT

    def _matches_filepath_pattern(self, filepath):
        '''Given a filepath, and a list of regex patterns, this function returns true
        if filepath matches any one of those patterns'''
        if not self.only_blame_patterns:
            return True

        for pattern in self.only_blame_patterns:
            if pattern.match(filepath):
                return True
        return False

    def _get_basepath(self, filename):
        for pattern in self.extract_base_path_patterns:
            match = pattern.match(filename)
            if match:
                return match.group(1)
        return None

    def _format_traceback(self, request, append_locals=True, show_full_stack=False,
                          linebreak="<br />", spacer="&nbsp;", start_bold="<strong>",
                          end_bold="</strong>", escape_func=cgi.escape):
        parts = []
        if request.exception_type:
            parts.append("{b}Exception Type:{xb} {type}{lb}".format(
                b=start_bold, xb=end_bold, type=request.exception_type, lb=linebreak))

        # Traceback
        parts.append("{b}Traceback (most recent call last):{xb}".format(b=start_bold, xb=end_bold))
        formatted_stack = [
            '{sp}{sp}File "{filename}", line {line}, in {function}{lb}{sp}{sp}{sp}{sp}{code}'.format(
                sp=spacer, lb=linebreak, filename=l.filename, line=l.line_number,
                function=l.function_name, code=escape_func(l.text),
            )
            for l in request.traceback
        ]
        parts.extend(formatted_stack)
        parts.append(escape_func(request.exception_message))

        # Frame Locals
        parts.append(linebreak * 2 + "{b}Stack Frame:{xb}".format(b=start_bold, xb=end_bold))
        types_to_show = [api_ttypes.LineType.KNOWN_ERROR,
                         api_ttypes.LineType.DEFAULT,
                         api_ttypes.LineType.RAISED_EXCEPTION]
        frames_to_show = [l for l in request.traceback if l.frame_locals is not None and
                          (self._get_line_type(l) in types_to_show or show_full_stack)]
        for l in frames_to_show:
            line_info = '{sp}{sp}{b}File "{filename}", line {line}, in {function}{xb}'.format(
                sp=spacer, filename=l.filename, line=l.line_number, function=l.function_name,
                b=start_bold, xb=end_bold,
            )
            local_vals = ['{sp}{sp}{sp}{sp}{name}={value}'.format(
                          sp=spacer, name=name, value=escape_func(value.decode("UTF-8", "replace")))
                          for name, value in sorted(l.frame_locals.items())]
            parts.append(line_info)
            parts.extend(local_vals or [spacer * 4 + "No variables in this frame"])

        # Additional Information
        if request.additional_info:
            parts.append(linebreak * 2 + "{b}Additional Information:{xb}".format(b=start_bold, xb=end_bold))
            parts.append(
                escape_func(request.additional_info.decode("UTF-8", "replace")).replace("\n", linebreak)
            )

        return linebreak.join(parts)


############################## THRIFT SERVICE ##############################

class FlawlessThriftServiceHandler(FlawlessServiceBaseClass):
    """Handler for Thrift server API"""

    ############################## CONSTANTS ##############################

    # Validates that email address is valid. Does not attempt to be RFC compliant
    #     local part: any alphanumeric or ., %, +, \, -, _
    #     domain part: any alphanumeric. Dashes or periods allowed as long as they are not followed
    #                                by a period
    #     top level domain: between 2 to 4 alpha chracters
    VALIDATE_EMAIL_PATTERN = \
        re.compile(r"^[A-Za-z0-9.%+\-_]+@(?:(?:[a-zA-Z0-9]+-?)*[a-zA-Z0-9]\.)+[A-Za-z]{2,4}$")

    ############################## Init ##############################

    def __init__(self, *args, **kwargs):
        super(FlawlessThriftServiceHandler, self).__init__(*args, **kwargs)
        self.number_of_git_blames_running = 0

        self.repository = get_repository(open_process_func=self.open_process_func)

        self.lock = threading.RLock()
        self.errors_seen = None
        self._refresh_errors_seen()

        self.persist_thread = self.thread_cls(target=self._run_background_update_thread)
        self.persist_thread.daemon = True
        self.persist_thread.start()

    ############################## Update Thread ##############################

    def _refresh_errors_seen(self, epoch_ms=None):
        prefix = self._partition_for_ms(epoch_ms)
        with self.lock:
            if self.errors_seen is None:
                self.errors_seen = self.storage_factory(prefix)
                self.errors_seen.open()
            elif prefix != self.errors_seen.partition:
                # Order matters here since there can be a race condition if not done correctly
                old_errors_seen = self.errors_seen
                new_errors_seen = self.storage_factory(prefix)
                new_errors_seen.open()
                self.errors_seen = new_errors_seen
                old_errors_seen.sync()
                old_errors_seen.close()

    def _run_background_update_thread(self):
        while True:
            time.sleep(300)
            tasks_to_run = [
                lambda: self.errors_seen.sync(),
                lambda: self._refresh_errors_seen(),
                lambda: self.repository.update(),
                lambda: self._read_whitelist_configs(),
            ]
            # Run all items in try/except block because we don't want our background thread
            # to die.
            for task in tasks_to_run:
                try:
                    task()
                except:
                    self._handle_flawless_issue("<br />".join(traceback.format_exception(*sys.exc_info())))

    ############################## Misc Helper Funcs ##############################

    def ping(self):
        return True

    def _sendmail(self, to_addresses, subject, body):
        invalid_addresses = [e for e in to_addresses if not bool(self.VALIDATE_EMAIL_PATTERN.match(e))]
        if invalid_addresses:
            to_addresses = [e for e in to_addresses if e not in invalid_addresses]
            self._handle_flawless_issue(
                "Invalid email address found. Not sending to: %s" % ", ".join(invalid_addresses),
                log_func=log.warning,
            )

        msg = email.MIMEText.MIMEText(body.encode("UTF-8"), "html", "UTF-8")
        msg["From"] = config.smtp_from or "flawless@%s" % config.email_domain_name
        msg["To"] = ", ".join(to_addresses)
        msg["Subject"] = subject

        host, port = config.smtp_host.split(":")
        smtp_client = self.smtp_client_cls(host, int(port))

        if config.smtp_use_tls:
            smtp_client.starttls()
        if config.smtp_user and config.smtp_password:
            smtp_client.login(config.smtp_user, config.smtp_password)

        smtp_client.sendmail(msg["From"], to_addresses, msg.as_string())
        smtp_client.quit()

    def _get_email(self, email):
        '''Given an email address, check the email_remapping table to see if the email
        should be sent to a different address. This function also handles overriding
        the email domain if ignore_vcs_email_domain is set or the domain was missing'''
        if not email or "@" not in email:
            return None

        if email in self.email_remapping.remap:
            return self.email_remapping.remap[email]
        prefix, domain = email.split("@", 2)
        if prefix in self.email_remapping.remap:
            return self.email_remapping.remap[prefix]
        if "." not in domain or config.ignore_vcs_email_domain:
            return "%s@%s" % (prefix, config.email_domain_name)
        return email

    def _get_entry(self, entry, entry_tree):
        '''Helper function for retrieving a particular entry from the prefix trees'''
        for e in entry_tree[entry.filename]:
            if entry == e:
                return e

    def _handle_flawless_issue(self, message, log_func=log.error):
        log_func(message)
        if config.default_contact:
            self._sendmail([config.default_contact], "Unexpected problem on Flawless Server", message)

    ############################## Record Error ##############################

    def record_error(self, request):
        t = self.thread_cls(target=self._record_error, args=[request])
        t.start()

    def _record_error(self, request):
        log.debug("Recieved error from %s for %s" % (request.hostname, request.exception_message))

        # Skip ignored exceptions (ex: connection errors)
        if request.exception_type and request.exception_type in self.ignored_exceptions:
            return

        # Figure out which line in the stack trace is to blame for the error
        key, blamed_entry, email_recipients, was_whitelisted = self._blame_line(request.traceback)
        if not key:
            if not was_whitelisted:
                name_map = api_ttypes.LineType._VALUES_TO_NAMES
                line_types = [(stack_line.filename, name_map.get(self._get_line_type(stack_line)))
                              for stack_line in request.traceback]
                log.info("Unable to blame: %s" % str(line_types))
            return

        # If this error hasn't been reported before, then find the dev responsible
        err_info = None
        if key not in self.errors_seen:
            # If flawless is being flooded with errors, limit the number of git blames so the
            # service doesn't fall over. We don't use a thread safe counter, because 10
            # git blames is just a soft limit
            if self.number_of_git_blames_running > config.max_concurrent_git_blames:
                log.error("Unable to process %s because %d git blames already running" %
                          (str(key), self.number_of_git_blames_running))
                return
            try:
                self.number_of_git_blames_running += 1
                email, last_touched_ts = self.repository.blame(key.filename, key.line_number)
            finally:
                self.number_of_git_blames_running -= 1

            dev_email = self._get_email(email)
            if key.filename in self.disownerships:
                remapped_owners = {entry.email: entry.designated_email for entry in self.disownerships[key.filename]}
                dev_email = remapped_owners.get(dev_email, dev_email)

            last_touched_ts = last_touched_ts or 0
            cur_time = self._convert_epoch_ms(datetime.datetime).strftime("%Y-%m-%d %H:%M:%S")
            mod_time = self._convert_epoch_ms(datetime.datetime, epoch_ms=last_touched_ts * 1000)
            mod_time = mod_time.strftime("%Y-%m-%d %H:%M:%S")
            known_entry = self._get_entry(blamed_entry, self.known_errors)
            err_info = api_ttypes.ErrorInfo(error_count=1,
                                            developer_email=dev_email or "unknown",
                                            date=mod_time,
                                            email_sent=False,
                                            last_occurrence=cur_time,
                                            is_known_error=bool(known_entry),
                                            last_error_data=request)
            self.errors_seen[key] = err_info
            log.info("Error %s caused by %s on %s" % (str(key), dev_email, mod_time))

            if not dev_email:
                self._handle_flawless_issue("Unable to do blame for %s from %s. You may want to consider setting "
                                            "only_blame_filepaths_matching in your flawless.cfg " %
                                            (str(key), request.hostname))
                err_info.email_sent = True
                return
        # If we've already seen this error then update the error count
        elif key in self.errors_seen:
            err_info = self.errors_seen[key]
            err_info.error_count += request.error_count or 1
            err_info.last_error_data = request
            cur_dt = self._convert_epoch_ms(datetime.datetime)
            err_info.last_occurrence = cur_dt.strftime("%Y-%m-%d %H:%M:%S")
            self.errors_seen[key] = err_info

        # Figure out if we should send an email or not
        send_email = False
        known_entry = None
        if blamed_entry not in self.known_errors[blamed_entry.filename]:
            # If it is an unknown error, then it must meet certain criteria. The code must have been
            # touched after report_only_after_minimum_date so errors in old code can be ignored. It
            # also has to have occurred at least report_error_threshold times (although the client
            # is allowed to override that value).
            if (not err_info.email_sent and err_info.date >= config.report_only_after_minimum_date and
                    err_info.error_count >= (request.error_threshold or config.report_error_threshold)):
                send_email = True
        else:
            # If it is a known error, we allow fine grainted control of how frequently emails will
            # be sent. An email will be sent if it has passed the min_alert_threshold, and/or this
            # is the Nth occurrence as defined alert_every_n_occurrences. If it has passed
            # max_alert_threshold then no emails will be sent.
            known_entry = self._get_entry(blamed_entry, self.known_errors)
            if (known_entry.min_alert_threshold and err_info.error_count >= known_entry.min_alert_threshold
                    and not err_info.email_sent):
                send_email = True
            if (known_entry.alert_every_n_occurrences and
                    err_info.error_count % known_entry.alert_every_n_occurrences == 0):
                send_email = True
            if (known_entry.max_alert_threshold is not None
                    and err_info.error_count > known_entry.max_alert_threshold):
                send_email = False

        # Send email if applicable
        if send_email:
            self._send_error_email(request, key, err_info, blamed_entry, known_entry, email_recipients)

    def _send_error_email(self, request, err_key, err_info, blamed_entry, known_entry, email_recipients):
        email_body = []
        dev_email = self._get_email(err_info.developer_email)
        if dev_email:
            email_recipients.append(dev_email)

        # Add additional recipients that have registered for this error
        if blamed_entry.filename in self.watch_only_if_blamed:
            email_recipients.extend(self.watch_only_if_blamed[blamed_entry.filename])
        if known_entry:
            email_recipients.extend(known_entry.email_recipients or [])
            email_body.append(known_entry.email_header or "")

        email_body.append(self._format_traceback(request))
        email_body.append(
            "<br /><br /><a href='%s/add_known_error?%s'>Add to whitelist</a>" %
            (
                config.hostname,
                urllib.urlencode(
                    dict(filename=err_key.filename, function_name=err_key.function_name, code_fragment=err_key.text)
                )
            )
        )

        # Send the email
        log.info("Sending email for %s to %s" % (str(err_key), ", ".join(email_recipients)))
        self._sendmail(
            to_addresses=email_recipients,
            subject="Error on %s in %s" % (request.hostname, err_key.filename),
            body="<br />".join([s for s in email_body if s]),
        )
        err_info.email_sent = True
        self.errors_seen[err_key] = err_info


############################## WEB SERVICE ##############################

class FlawlessWebServiceHandler(FlawlessServiceBaseClass):
    """Handler for HTTP server to show state of the Flawless service"""

    def __init__(self, *args, **kwargs):
        super(FlawlessWebServiceHandler, self).__init__(*args, **kwargs)

    def index(self, *args, **kwargs):
        return self.get_weekly_error_report(*args, **kwargs)

    def _get_errors_seen_for_ts(self, timestamp):
        prefix = self._partition_for_ms(int(timestamp) * 1000 if timestamp else None)
        errors_seen = self.storage_factory(prefix)
        errors_seen.open()
        return errors_seen

    def _add_new_entry_to_config(self, key, entry, attr='identifiers'):
        class_map = dict(known_errors=api_ttypes.KnownErrorList,
                         building_blocks=api_ttypes.CodeIdentifierList,
                         third_party_whitelist=api_ttypes.CodeIdentifierList,
                         watch_list=api_ttypes.WatchList)
        config_storage = self.storage_factory(partition=None)
        config_storage.open()
        current_value = config_storage[key] or class_map[key]()
        getattr(current_value, attr).append(entry)
        current_value.last_update_ts = self._epoch_ms()
        config_storage[key] = current_value
        config_storage.sync()
        config_storage.close()

    def _construct_instance(self, params, cls):
        THRIFT_SPEC_NAME_FIELD = 2
        THRIFT_SPEC_TYPE_FIELD = 1
        THRIFT_SPEC_SUBTYPE_FIELD = 3
        init_args = inspect.getargspec(cls.__init__).args
        whitelist_attrs = [s for s in init_args if s != 'self']
        args = dict((k, params.get(k)) for k in whitelist_attrs)
        arg_type_map = dict()

        # Build map of fields to type based on the thrift spec
        for spec in cls.thrift_spec:
            if not spec or len(spec) < 3:
                continue
            if spec[THRIFT_SPEC_TYPE_FIELD] == TType.BOOL:
                arg_type_map[spec[THRIFT_SPEC_NAME_FIELD]] = bool
            elif spec[THRIFT_SPEC_TYPE_FIELD] == TType.I64 or spec[THRIFT_SPEC_TYPE_FIELD] == TType.I32:
                arg_type_map[spec[THRIFT_SPEC_NAME_FIELD]] = int
            elif spec[THRIFT_SPEC_TYPE_FIELD] == TType.LIST and spec[THRIFT_SPEC_SUBTYPE_FIELD][0] == TType.STRING:
                arg_type_map[spec[THRIFT_SPEC_NAME_FIELD]] = lambda v: [s.strip() for s in v.split(',')]

        # Cast args to the appropriate type
        for field, value in args.items():
            if value and field in arg_type_map:
                args[field] = arg_type_map[field](value)

        new_entry = cls(**args)
        return new_entry

    def get_weekly_error_report(self, timestamp=None, include_known_errors=False,
                                include_modified_before_min_date=False):
        errors_seen = self._get_errors_seen_for_ts(timestamp)
        html_parts = ["<html><head><title>Error Report</title></head><body>"]

        grouped_errors = collections.defaultdict(list)
        developer_score = collections.defaultdict(int)
        for key, value in errors_seen.iteritems():
            if ((not value.is_known_error or include_known_errors) and
                    (value.date >= config.report_only_after_minimum_date or include_modified_before_min_date)):
                grouped_errors[value.developer_email].append((key, value))
                developer_score[value.developer_email] += value.error_count

        for developer, score in sorted(developer_score.items(), key=lambda t: t[1], reverse=True):
            html_parts.append("<strong id=\"%s\">%s (score: %d)</strong>" % (developer.replace('"', '\''), developer, score))
            for err_key, err_info in grouped_errors[developer]:
                html_parts.append("Number of Occurrences: " + str(err_info.error_count))
                html_parts.append("Last Occurred: " + err_info.last_occurrence)
                html_parts.append("Filename: " + err_key.filename)
                html_parts.append("Function Name: " + err_key.function_name)
                html_parts.append("Line Number: " + str(err_key.line_number))
                html_parts.append("Date Committed: " + err_info.date)
                html_parts.append("Email Sent: " + str(err_info.email_sent))
                params = copy.copy(err_key.__dict__)
                if timestamp:
                    params["timestamp"] = timestamp
                view_url = "%s/view_traceback?%s" % (config.hostname, urllib.urlencode(params))
                html_parts.append("<a href='%s'>view traceback</a>" % view_url)
                html_parts.append("<br />")
            html_parts.append("<br />")

        if not grouped_errors:
            html_parts.append("Wow, no errors. Great job!")
        return "<br />".join(html_parts)

    def view_traceback(self, filename="", function_name="", text="", line_number="", timestamp=None):
        errors_seen = self._get_errors_seen_for_ts(timestamp)
        err_key = api_ttypes.ErrorKey(filename=filename, function_name=function_name,
                                      text=text, line_number=int(line_number))

        err_info = errors_seen[err_key]
        if err_info:
            datastr = self._format_traceback(err_info.last_error_data)
        else:
            datastr = "Not Found"

        return """
            <html>
                <head>
                    <title>Flawless Traceback</title>
                </head>
                <body style='font-family: courier; font-size: 10pt'>
                    {data}
                </body>
            </html>
        """.format(data=datastr)

    def admin(self):
        return """
            <html>
                <head>
                    <title>Flawless Admin Panel</title>
                </head>
                <body>
                <div>
                    <b>Change Configuration</b><br />
                    <a href="add_known_error">Add Known Error</a><br />
                    <a href="add_watch">Add File Watcher</a><br />
                    <a href="remap_email">Remap Invalid Email Address</a><br />
                    <a href="disown_file">Disown a File</a><br />
                    <a href="add_ignored_exception">Add Ignored Exception Type</a><br />
                    <br /><br />
                    <b>View Configuration</b><br />
                    <a href="view_config?key=building_blocks">View Building Blocks</a><br />
                    <a href="view_config?key=third_party_whitelist">View Thirdparty Whitelist</a><br />
                    <a href="view_config?key=known_errors">View Whitelisted Errors</a><br />
                    <a href="view_config?key=ignored_exceptions">View Ignored Exception Types</a><br />
                    <a href="view_config?key=watch_list">View File Watch List</a><br />
                    <a href="view_config?key=disownership_list">View File Disownership List</a><br />
                    <a href="view_config?key=email_remapping">View Email Remapping</a><br />
                </div>
             </body>
            </html>
        """

    ############################## Add New Known Error ##############################

    def add_known_error(self, filename="", function_name="", code_fragment=""):
        code_fragment = cgi.escape(code_fragment)
        return """
            <html>
                <head>
                    <title>Add Known Error</title>
                </head>
                <body>
                <div>
                    Instructions: Fill out the file path, function name and code fragment for the known error.
                    If function name or code fragment are left empty, then they are treated as wildcards.<br />
                    Just entering file path, function name and code fragment will whitelist the error and stop
                    all emails about it. If you want to continue emails, but at a lower (or higher)
                    frequency or threshold you can use the optional fields.
                </div><br /><br />
                <form action='save_known_error' method='POST'>
                    <table>
                        <tr><td>* = Required</td></tr>
                        <tr>
                            <td>* File Path:</td>
                            <td><input name='filename' type='text' value='{filename}' size='50'/></td>
                        </tr>
                        <tr>
                            <td>* Function Name:</td>
                            <td><input name='function_name' type='text'value='{function_name}' size='50'/></td>
                        </tr>
                        <tr>
                            <td>* Code Fragment:</td>
                            <td><textarea name='code_fragment' rows='1' cols='50'/>{code_fragment}</textarea></td>
                        </tr>
                        <tr>
                            <td>* Error Type:</td>
                            <td>
                                <select name='type'>
                                    <option value='known_errors' selected>Add to Known Errors</option>
                                    <option value='building_blocks'>Mark as Library Code</option>
                                    <option value='third_party_whitelist'>Add to Ignored Thirdparty Errors</option>
                                </select>
                            </td>
                        </tr>
                        <tr><td>&nbsp</td></tr>
                        <tr><td><strong>Following section is only for known errors</strong></td></tr>
                        <tr><td>Must set one of the following **</td></tr>
                        <tr>
                            <td>** Minimum Alert Threshold:</td>
                            <td><input name='min_alert_threshold' type='text' /></td>
                        </tr>
                        <tr>
                            <td>** Maximum Alert Threshold:</td>
                            <td><input name='max_alert_threshold' type='text' /></td>
                        </tr>
                        <tr>
                            <td>** Alert Every N Occurrences:</td>
                            <td><input name='alert_every_n_occurrences' type='text' /></td>
                        </tr>
                        <tr>
                            <td>Email Recipients CSV:</td>
                            <td><input name='email_recipients' type='text' size='50'/></td>
                        </tr>
                        <tr>
                            <td>Email Header:</td>
                            <td><textarea name='email_header' rows='5' cols='50'></textarea></td>
                        </tr>
                    </table>
                    <input type='submit'></input>
                </form>
             </body>
            </html>
        """.format(**dict(locals().items()))

    def save_known_error(self, request):
        params = dict(urlparse.parse_qsl(request))
        class_map = dict(known_errors=api_ttypes.KnownError, building_blocks=api_ttypes.CodeIdentifier,
                         third_party_whitelist=api_ttypes.CodeIdentifier)
        new_entry = self._construct_instance(params, class_map[params['type']])
        self._add_new_entry_to_config(params['type'], new_entry)

        return "<html><body>SUCCESS</body></html>"

    def add_watch(self):
        return """
            <html>
                <head>
                    <title>Add Watch</title>
                </head>
                <body>
                <div>
                    Instructions: Fill out the file path & email to send reports to.
                </div><br /><br />
                <form action='save_watch' method='POST'>
                    <table>
                        <tr><td>* = Required</td></tr>
                        <tr>
                            <td>* File Path:</td>
                            <td><input name='filepath' type='text' size='50'/></td>
                        </tr>
                        <tr>
                            <td>* Email:</td>
                            <td><input name='email' type='text' size='50'/></td>
                        </tr>
                        <tr>
                            <td>* Watch Type:</td>
                            <td>
                                <select name='watch_all_errors'>
                                    <option value='true' selected>Any Error</option>
                                    <option value='false'>Only Blamed Errors</option>
                                </select>
                            </td>
                        </tr>
                    </table>
                    <input type='submit'></input>
                </form>
             </body>
            </html>
        """

    def save_watch(self, request):
        params = dict(urlparse.parse_qsl(request))
        params['watch_all_errors'] = params['watch_all_errors'] == 'true'
        new_entry = self._construct_instance(params, api_ttypes.WatchFileEntry)
        self._add_new_entry_to_config("watch_list", new_entry, attr="watches")
        return "<html><body>SUCCESS</body></html>"

    def remap_email(self):
        return """
            <html>
                <head>
                    <title>Remap Email</title>
                </head>
                <body>
                <div>
                    Instructions: Fill out the old email & the new email to send reports to.
                </div><br /><br />
                <form action='save_remap_email' method='POST'>
                    <table>
                        <tr><td>* = Required</td></tr>
                        <tr>
                            <td>* Old Email:</td>
                            <td><input name='old_email' type='text' size='50'/></td>
                        </tr>
                        <tr>
                            <td>* New Email:</td>
                            <td><input name='new_email' type='text' size='50'/></td>
                        </tr>
                    </table>
                    <input type='submit'></input>
                </form>
             </body>
            </html>
        """

    def save_remap_email(self, request):
        params = dict(urlparse.parse_qsl(request))
        config_storage = self.storage_factory(partition=None)
        config_storage.open()
        current_value = config_storage["email_remapping"] or api_ttypes.EmailRemapping()
        current_value.remap[params["old_email"]] = params["new_email"]
        current_value.last_update_ts = self._epoch_ms()
        config_storage["email_remapping"] = current_value
        config_storage.sync()
        config_storage.close()
        return "<html><body>SUCCESS</body></html>"

    def disown_file(self):
        return """
            <html>
                <head>
                    <title>Disown File</title>
                </head>
                <body>
                <div>
                    Instructions: Fill out filepath, your email & the new email to send reports to.
                </div><br /><br />
                <form action='save_disown_file' method='POST'>
                    <table>
                        <tr><td>* = Required</td></tr>
                        <tr>
                            <td>* Filepath:</td>
                            <td><input name='filepath' type='text' size='50'/></td>
                        </tr>
                        <tr>
                            <td>* Your Email:</td>
                            <td><input name='email' type='text' size='50'/></td>
                        </tr>
                        <tr>
                            <td>* New Email:</td>
                            <td><input name='designated_email' type='text' size='50'/></td>
                        </tr>
                    </table>
                    <input type='submit'></input>
                </form>
             </body>
            </html>
        """

    def save_disown_file(self, request):
        params = dict(urlparse.parse_qsl(request))
        new_entry = self._construct_instance(params, api_ttypes.FileDisownershipEntry)
        self._add_new_entry_to_config("disownership_list", new_entry, attr="disownerships")
        return "<html><body>SUCCESS</body></html>"

    def add_ignored_exception(self):
        return """
            <html>
                <head>
                    <title>Add Ignored Exception</title>
                </head>
                <body>
                <div>
                    Instructions: Enter the full module path for the exception (ex: exceptions.ValueError)
                </div><br /><br />
                <form action='save_ignored_exceptions' method='POST'>
                    <table>
                        <tr><td>* = Required</td></tr>
                        <tr>
                            <td>* Exception Path:</td>
                            <td><input name='exc_name' type='text' size='50'/></td>
                        </tr>
                    </table>
                    <input type='submit'></input>
                </form>
             </body>
            </html>
        """

    def save_ignored_exceptions(self, request):
        params = dict(urlparse.parse_qsl(request))
        config_storage = self.storage_factory(partition=None)
        config_storage.open()
        current_value = config_storage["ignored_exceptions"] or api_ttypes.IgnoredExceptionList()
        if params['exc_name'] not in current_value.exceptions:
            current_value.exceptions.append(params['exc_name'])
        current_value.last_update_ts = self._epoch_ms()
        config_storage["ignored_exceptions"] = current_value
        config_storage.sync()
        config_storage.close()
        return "<html><body>SUCCESS</body></html>"

    def view_config(self, key):
        config_storage = self.storage_factory(partition=None)
        config_storage.open()
        current_value = config_storage[key]
        config_storage.close()

        if pprint:
            data = pprint.pformat(current_value)
        else:
            data = str(current_value)

        data = data.replace("\n", "<br />")
        return """
            <html>
                <head>
                    <title>Flawless Config</title>
                </head>
                <body style='font-family: courier; font-size: 10pt'>
                    <pre>
                        {data}
                    </pre>
                </body>
            </html>
        """.format(data=data)

    def check_health(self):
        parts = ["<html><body>OK<br/>"]
        for option in flawless.lib.config.OPTIONS:
            parts.append("%s: %s" % (option.name, str(getattr(config, option.name))))
        parts.append("</body></html>")
        return "<br />".join(parts)
