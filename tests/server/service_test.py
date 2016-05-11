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

import copy
import datetime
import email
import time
import unittest
import StringIO

from flawless.lib.storage.stub import StubStorage
import flawless.lib.config
import flawless.server.api.ttypes as api_ttypes
from flawless.server.service import FlawlessThriftServiceHandler
import flawless.server.server


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.popen_stub = POpenStub()
        self.popen_stub.stdout = StringIO.StringIO(
            "75563df6e9d1efe44b48f6643fde9ebbd822b0c5 25 25 1\n"
            "author John Egan\n"
            "author-mail <wishbone@shopkick.com>\n"
            "author-time %d\n"
            "author-tz -0800\n"
            "committer John Egan\n"
            "committer-mail <repo_master@shopkick.com>\n"
            "committer-time 1356245776\n"
            "committer-tz -0800\n"
            "summary Add more robust support for string keys\n"
            "previous 3491c7b8e298ec81dc7583163a118e7c2250999f safe_access.py\n"
            "filename safe_access.py\n"
            "                             ex: a.b.[myvar] where myvar is passed in as a kwarg\n"
            % int(time.mktime(datetime.datetime(2017, 7, 30).timetuple()))
        )

        self._set_stub_time(datetime.datetime(2020, 1, 1))
        self.smtp_stub = SMTPClientStub()
        self.file_open_stub = OpenFileStub()

        self.watchers = api_ttypes.WatchList([
            api_ttypes.WatchFileEntry(
                email="wilfred@shopkick.com",
                filepath="tools/furminator.py",
                watch_all_errors=True,
            ),

            api_ttypes.WatchFileEntry(
                email="lassie@shopkick.com",
                filepath="tools/furminator.py",
                watch_all_errors=True,
            ),
            api_ttypes.WatchFileEntry(
                email="wishbone@shopkick.com",
                filepath="lib/no/such/path/for/testing.py",
                watch_all_errors=True,
            ),
        ])

        self.third_party_whitelist = api_ttypes.CodeIdentifierList([
            api_ttypes.CodeIdentifier('facebook.py', 'post_treat_to_facebook',
                                      'urllib.urlencode(args), post_data)'),
            api_ttypes.CodeIdentifier(
                'SQLAlchemy-0.5.6-py2.6.egg/sqlalchemy/pool.py',
                'do_get',
                'raise exc.TimeoutError("QueuePool limit of size %d overflow %d ',
            ),
        ])

        self.known_errors = api_ttypes.KnownErrorList([
            api_ttypes.KnownError(
                'lib/doghouse/authentication.py',
                'check_auth',
                'raise errors.BadAuthenticationError("Something smells off...")',
                max_alert_threshold=0,
            ),
            api_ttypes.KnownError(
                filename='coreservices/waterbowl/rewards/water.py',
                function_name='make_external_api_ttypes_request',
                code_fragment='raise api_ttypes.WaterbowlError(error_code='
                              'api_ttypes.WaterbowlErrorCode.OUT_OF_WATER, message=str(e))',
                email_recipients=["wilfred@shopkick.com", "snoopy@shopkick.com"],
                email_header='NOTE: This error typically does not require dev team involvement.',
                alert_every_n_occurrences=1,
            ),
        ])

        self.building_blocks = api_ttypes.CodeIdentifierList([
            api_ttypes.CodeIdentifier('apps/shopkick/doghouse/lib/base.py',
                                      '_get_request_param',
                                      'raise errors.BadRequestError("Missing param %s" % name)'),
        ])

        self.ignored_exceptions = api_ttypes.IgnoredExceptionList(['exceptions.BananaException'])

        self.disowned_files = api_ttypes.FileDisownershipList([
            api_ttypes.FileDisownershipEntry(
                email='wishbone@shopkick.com',
                filepath='scripts',
                designated_email='lassie@shopkick.com'
            )
        ])

        self.config_storage_stub = StubStorage(partition=None)
        self.config_storage_stub["watch_list"] = self.watchers
        self.config_storage_stub["third_party_whitelist"] = self.third_party_whitelist
        self.config_storage_stub["known_errors"] = self.known_errors
        self.config_storage_stub["building_blocks"] = self.building_blocks
        self.config_storage_stub["ignored_exceptions"] = self.ignored_exceptions
        self.config_storage_stub["disownership_list"] = self.disowned_files
        self.errors_storage_stub = StubStorage(partition=None)

        self.saved_config = copy.deepcopy(flawless.lib.config.get().__dict__)
        self.test_config = flawless.lib.config.get()
        self.test_config.__dict__ = dict((o.name, o.default) for o in flawless.lib.config.OPTIONS)
        self.test_config.repo_dir = "/tmp"
        self.test_config.report_only_after_minimum_date = "2010-01-01"
        self.test_config.report_error_threshold = 1
        self.test_config.only_blame_filepaths_matching = [
            r"^coreservices(?!.*/thrift/).*$",
            r"lib/.*",
            r"tools/.*",
            r"scripts/.*"
        ]
        self.test_config.report_runtime_package_directory_names = ["site-packages"]
        self.test_config.config_dir_path = "../config"

        self.handler = FlawlessThriftServiceHandler(
            open_process_func=self.popen_stub,
            storage_factory=lambda partition: self.errors_storage_stub if partition else self.config_storage_stub,
            smtp_client_cls=self.smtp_stub,
            time_func=lambda: self.stub_time,
            thread_cls=ThreadStub,
        )

    def tearDown(self):
        super(BaseTestCase, self).tearDown()
        flawless.lib.config.get().__dict__ = self.saved_config

    def _set_stub_time(self, dt):
        self.stub_time = int(time.mktime(dt.timetuple()))

    def assertDictEquals(self, expected, actual):
        if expected == actual:
            return

        bad_keys = set(expected.keys()) ^ set(actual.keys())
        if bad_keys:
            keys_str = [str(key) for key in (set(expected.keys()) - set(actual.keys()))]
            errstr = "Keys not in second dict: %s" % "\n".join(keys_str)
            keys_str = [str(key) for key in (set(actual.keys()) - set(expected.keys()))]
            errstr += "\nKeys not in first dict:    %s" % "\n".join(keys_str)
            raise AssertionError("Missing/Extraneous keys:\n%s" % errstr)
        for key in expected.keys():
            if expected[key] != actual[key]:
                raise AssertionError("Value mismatch for key %s:\n%s\n%s" %
                                     (key, str(expected[key]), str(actual[key])))

    def assertEmailEquals(self, expected, actual):
        self.assertEquals(expected["from_address"], actual["from_address"])
        self.assertEquals(set(expected["to_addresses"]), set(actual["to_addresses"]))
        parsed_email = email.message_from_string(actual["body"])
        self.assertEquals(expected["from_address"], parsed_email["From"])
        self.assertEquals(set(expected["to_addresses"]), set(parsed_email["To"].split(", ")))
        self.assertEquals(expected["subject"], parsed_email["Subject"])
        self.assertTrue(expected["body"] in parsed_email.get_payload(decode=True))


class RecordErrorTestCase(BaseTestCase):

    def setUp(self):
        super(RecordErrorTestCase, self).setUp()

    def test_records_error(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/coreservices/service.py", 7, "serve", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
        )

        self.handler.record_error(req)
        self.assertDictEquals({
            api_ttypes.ErrorKey("coreservices/service.py", 7, "serve", "..."): api_ttypes.ErrorInfo(
                1, "wishbone@shopkick.com", "2017-07-30 00:00:00", True, "2020-01-01 00:00:00",
                is_known_error=False, last_error_data=req)},
            self.handler.errors_seen.dict)
        self.assertEqual(["git", "--git-dir=/tmp/.git", "--work-tree=/tmp", "blame",
                          "-p", "/tmp/coreservices/service.py", "-L", "7,+1"],
                         self.popen_stub.last_args)
        self.assertEmailEquals(dict(to_addresses=["wishbone@shopkick.com"],
                                    from_address="flawless@example.com",
                                    subject="Error on localhost in coreservices/service.py",
                                    body="email text",
                                    smtp_server_host_port=None),
                               self.smtp_stub.last_args)

    def test_records_error_with_thrift_in_file_name(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/coreservices/thrift_file.py", 7, "serve", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
        )

        self.handler.record_error(req)
        self.assertDictEquals({
            api_ttypes.ErrorKey("coreservices/thrift_file.py", 7, "serve", "..."): api_ttypes.ErrorInfo(
                1, "wishbone@shopkick.com", "2017-07-30 00:00:00", True, "2020-01-01 00:00:00",
                is_known_error=False, last_error_data=req)},
            self.handler.errors_seen.dict)

    def test_ignores_error_in_thrift_directory(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x"),
                       api_ttypes.StackLine("/site-packages/coreservices/thrift/file.py", 7, "serve", "...")],
            exception_message="email text",
            hostname="localhost",
        )

        self.handler.record_error(req)
        self.assertDictEquals({}, self.handler.errors_seen.dict)

    def test_ignores_ignored_exceptions(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/coreservices/service.py", 7, "serve", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            exception_type="exceptions.BananaException",
            hostname="localhost",
        )

        self.handler.record_error(req)
        self.assertDictEquals({}, self.handler.errors_seen.dict)

    def test_doesnt_report_errors_under_threshold(self):
        self.test_config.report_error_threshold = 2
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/coreservices/service.py", 7, "serve", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
        )

        self.handler.record_error(req)
        self.assertDictEquals({
            api_ttypes.ErrorKey("coreservices/service.py", 7, "serve", "..."): api_ttypes.ErrorInfo(
                1, "wishbone@shopkick.com", "2017-07-30 00:00:00", False, "2020-01-01 00:00:00",
                is_known_error=False, last_error_data=req)},
            self.handler.errors_seen.dict)
        self.assertEquals(None, self.smtp_stub.last_args)

    def test_uses_threshold_specified_in_request(self):
        self.test_config.report_error_threshold = 2
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/coreservices/service.py", 7, "serve", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
            error_threshold=1,
        )

        self.handler.record_error(req)

        self.assertEmailEquals(dict(to_addresses=["wishbone@shopkick.com"],
                                    from_address="flawless@example.com",
                                    cc_address=None,
                                    bcc_address=None,
                                    subject="Error on localhost in coreservices/service.py",
                                    body="email text",
                                    smtp_server_host_port=None),
                               self.smtp_stub.last_args)

    def test_always_alerts_on_red_alert_errors(self):
        self.test_config.report_error_threshold = 3
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/coreservices/service.py", 7, "serve", "..."),
                       api_ttypes.StackLine('/site-packages/coreservices/service/utils.py',
                                            9, "check_water_levels", '% (waterbowl_id, min_required_level))'),
                       api_ttypes.StackLine("/site-packages/coreservices/waterbowl/rewards/water.py",
                                            5,
                                            "make_external_api_ttypes_request",
                                            "raise api_ttypes.WaterbowlError(error_code=api_ttypes.WaterbowlErrorCode."
                                            "OUT_OF_WATER, message=str(e))")],
            exception_message="email text",
            hostname="localhost",
        )

        self.handler.record_error(req)

        # The 2 red alert recipients plus the developer responsible
        self.assertEmailEquals(dict(to_addresses=["wilfred@shopkick.com", "wishbone@shopkick.com",
                                                  "snoopy@shopkick.com"],
                                    from_address="flawless@example.com",
                                    cc_address=None,
                                    bcc_address=None,
                                    subject="Error on localhost in coreservices/waterbowl/rewards/water.py",
                                    body="email text",
                                    smtp_server_host_port=None),
                               self.smtp_stub.last_args)

    def test_email_includes_watchers(self):
        # Almost the same setup as test_uses_threshold_specified_in_request except the traceback includes
        # a path that Yen is watching
        self.test_config.report_error_threshold = 2
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/tools/furminator.py", 7, "fubar", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
            error_threshold=1,
        )

        self.handler.record_error(req)
        self.assertEmailEquals(dict(to_addresses=["wilfred@shopkick.com", "wishbone@shopkick.com", "lassie@shopkick.com"],
                                    from_address="flawless@example.com",
                                    cc_address=None,
                                    bcc_address=None,
                                    subject="Error on localhost in tools/furminator.py",
                                    body="email text",
                                    smtp_server_host_port=None),
                               self.smtp_stub.last_args)

    def test_email_includes_extra_information(self):
        # Traceback includes a path that has extra_information tagged on it
        self.test_config.report_error_threshold = 2
        req = api_ttypes.RecordErrorRequest(
            traceback=[
                api_ttypes.StackLine(
                    "/site-packages/coreservices/waterbowl/rewards/water.py",
                    5,
                    "make_external_api_ttypes_request",
                    "raise api_ttypes.WaterbowlError(error_code=api_ttypes.WaterbowlErrorCode."
                    "OUT_OF_WATER, message=str(e))"
                ),
            ],
            exception_message="email text",
            hostname="localhost",
            error_threshold=1,
            additional_info="extra stuff",
        )

        self.handler.record_error(req)

        self.assertEmailEquals(dict(to_addresses=["snoopy@shopkick.com",
                                                  "wilfred@shopkick.com",
                                                  "wishbone@shopkick.com"],
                                    from_address="flawless@example.com",
                                    cc_address=None,
                                    bcc_address=None,
                                    subject="Error on localhost in coreservices/waterbowl/rewards/water.py",
                                    body='NOTE: This error typically does not require dev team involvement.',
                                    smtp_server_host_port=None),
                               self.smtp_stub.last_args)
        body = email.message_from_string(self.smtp_stub.last_args["body"]).get_payload(decode=True)
        self.assertTrue("email text" in body)
        self.assertTrue("extra stuff" in body)

    def test_removes_duplicate_emails(self):
        # Almost the same setup as test_uses_threshold_specified_in_request except the traceback includes
        # a path that John is watching. Since he's also the developer who committed the buggy code, he is
        # the one and only email recipient.
        self.test_config.report_error_threshold = 2
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/lib/no/such/path/for/testing.py", 7, "fubar", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
            error_threshold=1,
        )

        self.handler.record_error(req)

        self.assertEmailEquals(dict(to_addresses=["wishbone@shopkick.com"],
                                    from_address="flawless@example.com",
                                    cc_address=None,
                                    bcc_address=None,
                                    subject="Error on localhost in lib/no/such/path/for/testing.py",
                                    body="email text",
                                    smtp_server_host_port=None),
                               self.smtp_stub.last_args)

    def test_doesnt_email_on_errors_before_cutoff_date(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/coreservices/service.py", 7, "serve", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
        )
        self.popen_stub.stdout = StringIO.StringIO(
            "75563df6e9d1efe44b48f6643fde9ebbd822b0c5 25 25 1\n"
            "author John Egan\n"
            "author-mail <wishbone@shopkick.com>\n"
            "author-time %d\n"
            "author-tz -0800\n"
            % int(time.mktime(datetime.datetime(2009, 7, 30).timetuple()))
        )

        self.handler.record_error(req)
        self.assertDictEquals({
            api_ttypes.ErrorKey("coreservices/service.py", 7, "serve", "..."): api_ttypes.ErrorInfo(
                1, "wishbone@shopkick.com", "2009-07-30 00:00:00", False,
                "2020-01-01 00:00:00", is_known_error=False, last_error_data=req)},
            self.handler.errors_seen.dict)
        self.assertEqual(None, self.smtp_stub.last_args)

    def test_records_error_only_once(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/coreservices/service.py", 7, "serve", "..."),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
        )
        self.handler.record_error(req)
        self._set_stub_time(datetime.datetime(2020, 1, 2))
        self.handler.record_error(req)

        self.assertDictEquals({
            api_ttypes.ErrorKey("coreservices/service.py", 7, "serve", "..."): api_ttypes.ErrorInfo(
                2, "wishbone@shopkick.com", "2017-07-30 00:00:00", True, "2020-01-02 00:00:00",
                is_known_error=False, last_error_data=req)},
            self.handler.errors_seen.dict)
        self.assertEqual(1, len(self.smtp_stub.args_list))

    def test_does_not_email_for_whitelisted_errors(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/lib/doghouse/authentication.py", 7, "check_auth",
                                            'raise errors.BadAuthenticationError("Something smells off...")')],
            exception_message="email text",
            hostname="localhost",
        )
        self.handler.record_error(req)

        self.assertDictEquals({
            api_ttypes.ErrorKey("lib/doghouse/authentication.py", 7, "check_auth",
                                'raise errors.BadAuthenticationError("Something smells off...")'
                                ): api_ttypes.ErrorInfo(1, "wishbone@shopkick.com", "2017-07-30 00:00:00",
                                                        False, "2020-01-01 00:00:00", is_known_error=True,
                                                        last_error_data=req)},
                              self.handler.errors_seen.dict)
        self.assertEquals(None, self.smtp_stub.last_args)

    def test_ignores_third_party_whitelisted_errors(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/SQLAlchemy-0.5.6-py2.6.egg/sqlalchemy/pool.py",
                                            7,
                                            "do_get",
                                            'raise exc.TimeoutError("QueuePool limit of size %d overflow %d '
                                            'reached, connection timed out, timeout %d" % (self.size(),'
                                            'self.overflow(), self._timeout))')],
            exception_message="email text",
            hostname="localhost",
        )
        self.handler.record_error(req)
        self.assertDictEquals({}, self.handler.errors_seen.dict)

    def test_ignores_third_party_whitelisted_errors_for_facebook(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/facebook.py",
                                            7,
                                            "post_treat_to_facebook",
                                            'urllib.urlencode(args), post_data)')],
            exception_message="email text",
            hostname="localhost",
        )
        self.handler.record_error(req)
        self.assertDictEquals({}, self.handler.errors_seen.dict)

    def test_traces_up_stack_trace_for_errors_originating_from_building_blocks(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/coreservices/service.py", 7, "serve", "..."),
                       api_ttypes.StackLine("/site-packages/apps/shopkick/doghouse/lib/base.py", 9,
                                            "_get_request_param",
                                            'raise errors.BadRequestError("Missing param %s" % name)')],
            exception_message="email text",
            hostname="localhost",
        )
        self.handler.record_error(req)

        self.assertDictEquals({
            api_ttypes.ErrorKey("coreservices/service.py", 7, "serve", "..."): api_ttypes.ErrorInfo(
                1, "wishbone@shopkick.com", "2017-07-30 00:00:00", True, "2020-01-01 00:00:00",
                is_known_error=False, last_error_data=req)},
            self.handler.errors_seen.dict)

    def test_handles_disowned_files(self):
        req = api_ttypes.RecordErrorRequest(
            traceback=[api_ttypes.StackLine("/site-packages/lib/test.py", 5, "test_func", "code"),
                       api_ttypes.StackLine("/site-packages/scripts/my_script.py", 7, "run_all", "code"),
                       api_ttypes.StackLine("/site-packages/thirdparty/3rdparty_lib.py", 9, "call", "x")],
            exception_message="email text",
            hostname="localhost",
        )

        self.handler.record_error(req)
        self.assertDictEquals({
            api_ttypes.ErrorKey("scripts/my_script.py", 7, "run_all", "code"): api_ttypes.ErrorInfo(
                1, "lassie@shopkick.com", "2017-07-30 00:00:00", True, "2020-01-01 00:00:00",
                is_known_error=False, last_error_data=req)},
            self.handler.errors_seen.dict)
        self.assertEqual(["git", "--git-dir=/tmp/.git", "--work-tree=/tmp", "blame",
                          "-p", "/tmp/scripts/my_script.py", "-L", "7,+1"],
                         self.popen_stub.last_args)
        self.assertEmailEquals(dict(to_addresses=["lassie@shopkick.com"],
                                    from_address="flawless@example.com",
                                    subject="Error on localhost in scripts/my_script.py",
                                    body="email text",
                                    smtp_server_host_port=None),
                               self.smtp_stub.last_args)


############################## Stubs ##############################
class LogStub(object):

    def __init__(self):
        self.last_args = None
        self.args_list = []

    def info(self, args):
        self.last_args = args
        self.args_list.append(args)


class POpenStub(object):

    def __init__(self):
        self.last_args = None
        self.stdout = StringIO.StringIO()
        self.stderr = StringIO.StringIO()

    def __call__(self, args, **kwargs):
        self.last_args = args
        return self


class SMTPClientStub(object):
    def __init__(self):
        self.args_list = []
        self.last_args = None
        self.host = None
        self.port = None

    def __call__(self, host, port):
        self.host = host
        self.port = port
        return self

    def sendmail(self, from_address, to_addresses, body):
        self.last_args = dict((k, v) for k, v in locals().items() if k != 'self')
        self.args_list.append(self.last_args)

    def quit(self):
        pass

    def login(self, user, password):
        pass


class OpenFileStub(object):
    def __init__(self):
        self.files = dict()
        self.current_file = None

    def set_file(self, filename, contents):
        self.files[filename] = StringIO.StringIO(contents)

    def __enter__(self, *args, **kwargs):
        return self.files[self.current_file]

    def __exit__(self, type, value, traceback):
        pass

    def __call__(self, filename, *args, **kwargs):
        self.current_file = filename
        return self


class ThreadStub(object):
    def __init__(self, target=None, args=[]):
        self.target = target
        self.args = args

    def start(self):
        if self.target.__name__ != '_run_background_update_thread':
            self.target(*self.args)


if __name__ == "__main__":
    unittest.main()
