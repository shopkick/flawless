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
import pickle
import re
import shutil
import smtplib
import subprocess
import threading
import time
import urllib
import urlparse

import flawless.lib.config
from flawless.lib.data_structures.persistent_dictionary import PersistentDictionary
from flawless.lib.data_structures import prefix_tree
from flawless.lib.version_control.repo import get_repository
from flawless.server import api

try:
  import simplejson as json
except:
  import json


log = logging.getLogger(__name__)
config = flawless.lib.config.get()

def dump_json(obj):
  return json.dumps(
      obj,
      indent=2,
      separators=(',', ': '),
      default=lambda o: dict((k,v) for k,v in o.__dict__.items() if v is not None),
  )


class CodeIdentifierBaseClass(object):
  def __init__(self, filename, function_name=None, code_fragment=None, min_alert_threshold=None,
               max_alert_threshold=None, email_recipients=None, email_header=None,
               alert_every_n_occurences=None):
    if not filename:
      raise ValueError("filename is required")
    self.filename = filename
    self.function_name = function_name
    # Condense whitespace to make comparissions more forgiving
    self.code_fragment = None if not code_fragment else re.sub("\s+", " ", code_fragment)

    # Optional fields
    self.min_alert_threshold = min_alert_threshold
    self.max_alert_threshold = max_alert_threshold
    self.email_recipients = email_recipients
    self.email_header = email_header
    self.alert_every_n_occurences = alert_every_n_occurences

  def to_json(self):
    return dump_json(dict((k,v) for k,v in self.__dict__.items() if v))

  def __str__(self):
    return repr(self)

  def __repr__(self):
    return "%s(%s)" % (
        self.__class__.__name__,
        ", ".join("%s=%s" % (k,repr(v)) for k,v in self.__dict__.items())
    )

  def __eq__(self, other):
    # We allow people to whitelist entire files, or functions by setting function_name to None or
    # code-fragment to None
    if not isinstance(other, CodeIdentifierBaseClass):
      return False
    if self.filename != other.filename:
      return False
    if self.function_name and other.function_name and self.function_name != other.function_name:
      return False
    if (self.code_fragment and other.code_fragment and self.code_fragment not in other.code_fragment
        and other.code_fragment not in self.code_fragment):
      return False

    return True


class KnownError(CodeIdentifierBaseClass):
  def __init__(self, *args, **kwargs):
    super(KnownError, self).__init__(*args, **kwargs)
    if (self.min_alert_threshold == self.max_alert_threshold == self.alert_every_n_occurences == None):
      raise ValueError("One of the following must be set: min_alert_threshold, "
                       "max_alert_threshold, or alert_every_n_occurences")

class StackTraceEntry(CodeIdentifierBaseClass):
  def __init__(self, filename, function_name, code_fragment):
    if not (filename and function_name and code_fragment):
      raise ValueError("filename, function_name, and code_fragment are required")
    super(StackTraceEntry, self).__init__(filename, function_name, code_fragment)


class BuildingBlock(CodeIdentifierBaseClass):
  def __init__(self, filename, function_name=None, code_fragment=None):
    super(BuildingBlock, self).__init__(filename, function_name, code_fragment)


class ThirdPartyWhitelistEntry(CodeIdentifierBaseClass):
  def __init__(self, filename, function_name=None, code_fragment=None):
    super(ThirdPartyWhitelistEntry, self).__init__(filename, function_name, code_fragment)



class FlawlessService(object):
  ############################## CONSTANTS ##############################

  # Validates that email address is valid. Does not attempt to be RFC compliant
  #   local part: any alphanumeric or ., %, +, \, -, _
  #   domain part: any alphanumeric. Dashes or periods allowed as long as they are not followed
  #                by a period
  #   top level domain: between 2 to 4 alpha chracters
  VALIDATE_EMAIL_PATTERN = \
    re.compile(r"^[A-Za-z0-9.%+\-_]+@(?:(?:[a-zA-Z0-9]+-?)*[a-zA-Z0-9]\.)+[A-Za-z]{2,4}$")

  ############################## Init ##############################

  def __init__(self, persistent_dict_cls=PersistentDictionary,
               thread_cls=threading.Thread,
               open_file_func=open, open_process_func=subprocess.Popen,
               smtp_client_cls=smtplib.SMTP, time_func=time.time):
    self.open_file_func = open_file_func
    self.open_process_func = open_process_func
    self.smtp_client_cls = smtp_client_cls
    self.persistent_dict_cls = persistent_dict_cls
    self.time_func = time_func
    self.thread_cls = thread_cls

    self.building_blocks = self._parse_whitelist_file("building_blocks", BuildingBlock)
    self.third_party_whitelist = self._parse_whitelist_file("third_party_whitelist",
                                                            ThirdPartyWhitelistEntry)
    self.known_errors = self._parse_whitelist_file("known_errors", KnownError)
    self.email_remapping = dict((e["remap"], e["to"]) for e in self._read_json_file("email_remapping"))
    self.watch_all_errors, self.watch_only_if_blamed = self._parse_watchers_file("watched_files")

    self.repository = get_repository(open_process_func=open_process_func)

    self.extract_base_path_pattern = re.compile('^.*/%s/?(.*)$' %
                                                config.report_runtime_package_directory_name)

    self.lock = threading.RLock()
    self.errors_seen = None
    self._refresh_errors_seen()

    self.persist_thread = self.thread_cls(target=self._run_background_update_thread)
    self.persist_thread.daemon = True
    self.persist_thread.start()

  ############################## Parse Config Files ##############################

  def _read_json_file(self, filename):
    # All configuration files are stored a json lists. The convention in this package
    # is to treats all strings in the top level list as comments
    with self.open_file_func(os.path.join(config.config_dir_path, filename), "r") as fh:
       return [o for o in json.loads(fh.read().strip()) if not isinstance(o, basestring)]

  def _parse_whitelist_file(self, filename, parsed_cls):
    parsed_objs = collections.defaultdict(list)
    for json_entry in self._read_json_file(filename):
      py_entry = parsed_cls(**json_entry)
      parsed_objs[py_entry.filename].append(py_entry)
    return parsed_objs

  def _parse_watchers_file(self, filename):
    all_error_tree = prefix_tree.FilePathTree()
    blame_only_tree = prefix_tree.FilePathTree()

    for watch in self._read_json_file(filename):
      tree = all_error_tree if watch.get("watch_all_errors") else blame_only_tree
      if watch["filepath"] not in tree:
        tree[watch["filepath"]] = list()
      tree[watch["filepath"]].append(watch["email"])

    # Set all_error_tree to have accumulator that will allow us to find everyone who was watching
    # the file or a parent of the file
    all_error_tree.set_accumulator(
      accumulator_intializer=list(),
      accumulator_func=lambda x, y: x + y if y else x,
    )

    return all_error_tree, blame_only_tree


  ############################## Update Thread ##############################

  def _file_path_for_ms(self, epoch_ms):
    timestamp_date = self._convert_epoch_ms(cls=datetime.date, epoch_ms=epoch_ms)
    timestamp_date = timestamp_date - datetime.timedelta(days=timestamp_date.isoweekday() % 7)
    file_path = os.path.join(config.data_dir_path,
                             "flawless-errors-" + timestamp_date.strftime("%Y-%m-%d"))
    return file_path

  def _refresh_errors_seen(self, epoch_ms=None):
    file_path = self._file_path_for_ms(epoch_ms)
    with self.lock:
      if self.errors_seen is None:
        self.errors_seen = self.persistent_dict_cls(file_path)
        self.errors_seen.open()
      elif file_path != self.errors_seen.get_path():
        # Order matters here since there can be a race condition if not done correctly
        old_errors_seen = self.errors_seen
        new_errors_seen = self.persistent_dict_cls(file_path)
        new_errors_seen.open()
        self.errors_seen = new_errors_seen
        old_errors_seen.close()

  def _run_background_update_thread(self):
    while True:
      time.sleep(300)
      tasks_to_run = [
        lambda: self.errors_seen.sync(),
        lambda: self._refresh_errors_seen(),
        lambda: self.repository.update(),
      ]
      # Run all items in try/except block because we don't want our background thread
      # to die.
      for task in tasks_to_run:
        try:
          task()
        except Exception as e:
          log.exception(e)

  ############################## Misc Helper Funcs ##############################

  def _sendmail(self, to_addresses, subject, body):
    host, port = config.smtp_host.split(":")
    smtp_client = self.smtp_client_cls(host, int(port))

    invalid_addresses = [e for e in to_addresses if
                         not bool(self.VALIDATE_EMAIL_PATTERN.match(e))]
    if invalid_addresses:
      to_addresses = [e for e in to_addresses if e not in invalid_addresses]
      log.warning("Invalid email address found. Not sending to: %s" %
                  ", ".join(invalid_addresses))

    msg = email.MIMEText.MIMEText(body.encode("UTF-8"), "html", "UTF-8")
    msg["From"] = "error_report@%s" % config.email_domain_name
    msg["To"] = ", ".join(to_addresses)
    msg["Subject"] = subject

    if config.smtp_user and config.smtp_password:
      smtp_client.login(config.smtp_user, config.smtp_password)
    smtp_client.sendmail(msg["From"], to_addresses, msg.as_string())
    smtp_client.quit()

  def _get_email(self, email):
    '''Given an email address, check the email_remapping table to see if the email
    should be sent to a different address. This function also handles overriding
    the email domain if ignore_vcs_email_domain is set or the domain was missing'''
    if email in self.email_remapping:
      return self.email_remapping[email]
    prefix, domain = email.split("@", 2)
    if prefix in self.email_remapping:
      return self.email_remapping[prefix]
    if "." not in domain or config.ignore_vcs_email_domain:
      return "%s@%s" % (prefix, config.email_domain_name)
    return email

  def _convert_epoch_ms(self, cls, epoch_ms=None):
    if not epoch_ms:
      epoch_ms = int(self.time_func() * 1000)
    return cls.fromtimestamp(epoch_ms / 1000.)

  def _matches_path_list(self, filepath, path_list):
    '''Given a filepath, and a list of filepath fragments, this function returns true
    if filepath contains any one of those fragments'''
    for path in path_list:
      if path and path in filepath:
        return True
    return False

  def _get_entry(self, entry, entry_tree):
    '''Helper function for retrieving a particular entry from the prefix trees'''
    for e in entry_tree[entry.filename]:
      if entry == e:
        return e

  def _format_traceback(self, request, append_additional_info=True,
                        linebreak="<br />", spacer="&nbsp;"):
    parts = []
    parts.append("Traceback (most recent call last):")
    formatted_stack = [
      '{sp}{sp}File "{filename}", line {line}, in {function}{lb}{sp}{sp}{sp}{sp}{code}'.format(
        sp=spacer, lb=linebreak, filename=l.filename, line=l.line_number,
        function=l.function_name, code=l.text,
      )
      for l in request.traceback
    ]
    parts.extend(formatted_stack)
    parts.append(request.exception_message)

    if append_additional_info and request.additional_info:
      parts.append(linebreak + "Additional Information:")
      parts.append(request.additional_info.decode("UTF-8", "replace").replace("\n", linebreak))

    return linebreak.join(parts)

  ############################## Public API Funcs ##############################

  def record_error(self, request):
      t = self.thread_cls(target=self._record_error, args=[request])
      t.start()

  def _blame_line(self, traceback):
    '''Figures out which line in traceback is to blame for the error.
    Returns a 3-tuple of (api.ErrorKey, StackTraceEntry, [email recipients])'''
    key = None
    blamed_entry = None
    email_recipients = []
    for stack_line in traceback:
      match = self.extract_base_path_pattern.match(stack_line.filename)
      if match:
        filepath = match.group(1)
        entry = StackTraceEntry(filepath, stack_line.function_name, stack_line.text)
        if (self._matches_path_list(filepath, config.report_exclude_filepaths_containing) and
            not self._matches_path_list(filepath, config.report_include_filepaths_containing)):
          continue
        elif entry in self.third_party_whitelist[filepath]:
          return None, None, None
        elif entry not in self.building_blocks[filepath]:
          blamed_entry = entry
          key = api.ErrorKey(filepath, stack_line.line_number,
                             stack_line.function_name, stack_line.text)
          if filepath in self.watch_all_errors:
            email_recipients.extend(self.watch_all_errors[filepath])
    return (key, blamed_entry, email_recipients)


  def _record_error(self, request):
    # Parse request
    request = api.RecordErrorRequest.loads(request)

    # Figure out which line in the stack trace is to blame for the error
    key, blamed_entry, email_recipients = self._blame_line(request.traceback)
    if not key:
      return

    # If this error hasn't been reported before, then find the dev responsible
    err_info = None
    if key not in self.errors_seen:
      email, last_touched_ts = self.repository.blame(key.filename, key.line_number)
      if email:
        cur_time = self._convert_epoch_ms(datetime.datetime).strftime("%Y-%m-%d %H:%M:%S")
        mod_time = self._convert_epoch_ms(datetime.datetime, epoch_ms=last_touched_ts * 1000)
        mod_time = mod_time.strftime("%Y-%m-%d %H:%M:%S")
        known_entry = self._get_entry(blamed_entry, self.known_errors)
        err_info = api.ErrorInfo(error_count=1,
                                 developer_email=self._get_email(email),
                                 date=mod_time,
                                 email_sent=False,
                                 last_occurrence=cur_time,
                                 is_known_error=bool(known_entry),
                                 last_error_data=request)
        self.errors_seen[key] = err_info
        log.info("Error %s caused by %s on %s" % (str(key), email, mod_time))
    # If we've already seen this error then update the error count
    elif key in self.errors_seen:
      err_info = self.errors_seen[key]
      err_info.error_count += 1
      err_info.last_error_data = request
      cur_dt = self._convert_epoch_ms(datetime.datetime)
      err_info.last_occurrence = cur_dt.strftime("%Y-%m-%d %H:%M:%S")
      self.errors_seen[key] = err_info

    if not err_info:
      log.warn("Unable to do blame for %s" % str(err_info))
      return

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
      # is the Nth occurrence as defined alert_every_n_occurences. If it has passed
      # max_alert_threshold then no emails will be sent.
      known_entry = self._get_entry(blamed_entry, self.known_errors)
      if (known_entry.min_alert_threshold and err_info.error_count >= known_entry.min_alert_threshold
          and not err_info.email_sent):
        send_email = True
      if (known_entry.alert_every_n_occurences and
            err_info.error_count % known_entry.alert_every_n_occurences == 0):
        send_email = True
      if known_entry.max_alert_threshold and err_info.error_count > known_entry.max_alert_threshold:
        send_email = False

    # Send email if applicable
    if send_email:
      email_body = []
      email_recipients.append(self._get_email(err_info.developer_email))

      # Add additional recipients that have registered for this error
      if blamed_entry.filename in self.watch_only_if_blamed:
        email_recipients.extend(self.watch_only_if_blamed[blamed_entry.filename])
      if known_entry:
        email_recipients.extend(known_entry.email_recipients or [])
        email_body.append(known_entry.email_header or "")

      email_body.append(self._format_traceback(request))
      email_body.append(
        "<br /><br /><a href='http://%s/add_known_error?%s'>Add to whitelist</a>" %
        (config.hostname + ":" + str(config.port),
         urllib.urlencode(
           dict(filename=key.filename, function_name=key.function_name, code_fragment=key.text)
         )
        )
      )

      # Send the email
      log.info("Sending email for %s to %s" % (str(key), ", ".join(email_recipients)))
      self._sendmail(
          to_addresses=email_recipients,
          subject="Error on %s in %s" % (request.hostname, key.filename),
          body="<br />".join([s for s in email_body if s]),
      )
      err_info.email_sent = True
      self.errors_seen[key] = err_info


  def index(self, *args, **kwargs):
    return self.get_weekly_error_report(*args, **kwargs)

  def get_weekly_error_report(self, timestamp=None, include_known_errors=False,
                              include_modified_before_min_date=False):
    file_path = self._file_path_for_ms(int(timestamp) * 1000) if timestamp else None
    retdict = dict()
    if timestamp is None or self.errors_seen.get_path() == file_path:
      retdict = self.errors_seen.dict
    else:
      report = self.persistent_dict_cls(file_path)
      report.open()
      retdict = report.dict
    html_parts = ["<html><head><title>Error Report</title></head><body>"]

    grouped_errors = collections.defaultdict(list)
    developer_score = collections.defaultdict(int)
    for key, value in retdict.items():
      if ((not value.is_known_error or include_known_errors) and
          (value.date >= config.report_only_after_minimum_date or include_modified_before_min_date)):
        grouped_errors[value.developer_email].append((key, value))
        developer_score[value.developer_email] += value.error_count

    for developer, score in sorted(developer_score.items(), key=lambda t: t[1], reverse=True):
      html_parts.append("<strong>%s (score: %d)</strong>" % (developer, score))
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
        view_url = "http://%s/view_traceback?%s" % (config.hostname + ":" + str(config.port),
                                                    urllib.urlencode(params))
        html_parts.append("<a href='%s'>view traceback</a>" % view_url)
        html_parts.append("<br />")
      html_parts.append("<br />")

    if not grouped_errors:
      html_parts.append("Wow, no errors. Great job!")
    return "<br />".join(html_parts)

  def view_traceback(self, filename="", function_name="", text="", line_number="", timestamp=None):
    file_path = self._file_path_for_ms(int(timestamp) * 1000) if timestamp else None
    errdict = dict()
    if timestamp is None or self.errors_seen.get_path() == file_path:
      errdict = self.errors_seen.dict
    else:
      report = self.persistent_dict_cls(file_path)
      report.open()
      errdict = report.dict

    err_key = api.ErrorKey(filename=filename, function_name=function_name,
                           text=text, line_number=line_number)
    err_info = errdict.get(err_key)
    datastr = "Not Found"
    if err_info:
      datastr = self._format_traceback(err_info.last_error_data)
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
              <td><input name='alert_every_n_occurences' type='text' /></td>
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
    class_map = dict(known_errors=KnownError, building_blocks=BuildingBlock,
                     third_party_whitelist=ThirdPartyWhitelistEntry)
    cls = class_map[params['type']]

    whitelist_attrs = [s for s in inspect.getargspec(cls.__init__).args if s != 'self']
    new_entry = cls(**dict((k,params.get(k)) for k in whitelist_attrs))
    filename = os.path.join(config.config_dir_path, params['type'])

    with self.open_file_func(filename, "r") as fh:
      contents = json.load(fh)
    with self.open_file_func(filename + ".tmp", "w") as fh:
      contents.append(new_entry)
      fh.write(dump_json(contents))
    shutil.move(filename + ".tmp", filename)

    getattr(self, params['type'])[new_entry.filename].append(new_entry)
    return "<html><body>SUCCESS</body></html>"

  def check_health(self):
    parts = ["<html><body>OK<br/>"]
    for option in flawless.lib.config.OPTIONS:
      parts.append("%s: %s" % (option.name, str(getattr(config, option.name))))
    parts.append("</body></html>")
    return "<br />".join(parts)

