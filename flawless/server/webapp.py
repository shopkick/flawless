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
import collections
import inspect
import logging
import urllib
import urlparse


from thrift.Thrift import TType

import flawless.lib.config
from flawless.lib.utils import dump_json
import flawless.server.api.ttypes as api_ttypes
from flawless.server.service import FlawlessServiceBaseClass


log = logging.getLogger(__name__)
config = flawless.lib.config.get()


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
                         watch_list=api_ttypes.WatchList,
                         disownership_list=api_ttypes.FileDisownershipList)
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
            datastr = self._format_traceback(err_info, include_err_info=True)
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

        data = dump_json(current_value)
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