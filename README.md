Flawless
========

Flawless is a simple Python framework developed at shopkick for detecting bugs in a production
environment. Flawless traps exceptions and then sends an email to the developer that last touched
the line of code responsible for the exception. Flawless integrates with git and uses
git-blame to determine which developer to email.


Project website: [https://github.com/shopkick/flawless](https://github.com/shopkick/flawless)


4 Step Setup Guide
------------------

1. Install Flawless. After this step you should have an executable named flawless in your path.

    $> python setup.py install

2. Setup the Flawless server. Go to the server which you want to host the Flawless backend. Then
use the following command to start a short questionnaire to setup the server.

    $> flawless configure

3. Start the Flawless server

    $> flawless start -conf path/to/flawless.cfg

4. Integrate the Flawless client into your code. If you are running a WSGI application such as
django or pylons/pyramid, simply add the flawless.client.middleware to your application. Otherwise
you can wrap particular functions or entire classes by using flawless.client.decorators.

    Tip: Edit flawless.client.default.py and set the default host:port for your Flawless server



How it Works
------------

The Flawless client wraps your code with a try/except block. When an exception is caught it then
sends the entire traceback to the Flawless server. The Flawless server then aggregates exception
reports from clients and figures out which line of code caused the exception. Once the line that
caused the exception is identified, Flawless runs "git blame" to determine the email address of
the developer that last touched that line of code. Flawless then sends the developer an email with
the traceback.

Exceptions can be whitelisted if they are expected. To whitelist an exception you must specify
the filename, function name, and the text from the line of code being whitelisted in the appropriate
config file. Alternatively, exception emails include a link to automatically add an exception to
the whitelist. It is possible to whitelist all exceptions from a particular function by leaving the
line of code text blank. Likewise, an entire file can be whitelisted by leaving the line of code and
function blank.


Server Public API Endpoints
---------------------------

**/get\_weekly\_error\_report** - Shows all errors that happened this week in a leaderboard style format

     Parameters:
       timestamp (optional) - Specify which week you want to view. Default is the current week.
       include_known_errors (optional) - Include errors from config/known_errors. Default is False.

**/check\_health** - Check if the server is up and running. Also displays server's configuration
parameters

**/add\_known\_error** - Webpage in which you can whitelist errors

**/view\_traceback** - View the most recent traceback for a particular error

     Parameters:
       filename (required) - Specify the filename in which the error occurred
       function_name (required) - Specify the name of the function in which the error occurred
       line_number (required) - Specify the line number on which the error occurred
       text (required) - Specify the full text that appears on line_number
       timestamp (optional) - Specify which week you want to view. Default is the current week.


Configuration Files Reference
-----------------------------

**config/building\_blocks:** This is a list of library code functions that can raise an exception.
Adding an entry here causes the blame to be transferred to the caller of the library
rather than blaming the author of the library. See file for example.

     Fields:
       filename - The path to the file being whitelisted (not including the site-packages directory)
       function_name - The name of the function being whitelisted. This value can be set to None to
             act as a wildcard.
       code_fragment - The actual text from the line of code being whitelisted. This value can be
             set to None to act as a wildcard.


**config/known\_errors:** This is a list of known errors that happen. Reporting can be customized to
completely ignore the error, to only alert after a minimum number of occurrences; or to alert every
N occurences. See file for example.

     Fields:
       filename - The path to the file being whitelisted (not including the site-packages directory)
       function_name - The name of the function being whitelisted. This value can be set to None to
             act as a wildcard.
       code_fragment - The actual text from the line of code being whitelisted. This value can be
             set to None to act as a wildcard.
       min_alert_threshold - (optional) The minimum number of occurrences before Flawless will
             report this error.
       max_alert_threshold - (optional) The maximum number of occurrences before Flawless will
             stop reporting this error
       alert_every_n_occurences - (optional) Flawless will report this error every N occurrences
       email_recipients - (optional) List of email addresses to include on error reports for this
             error
       email_header - (optional) Extra text to place at the top of emails for this error


**config/third\_party\_whitelist:** This is a list of errors that can be generated by thirdparty
libraries that should be completely ignored (ex: network connection errors). See file for example.

     Fields:
       filename - The path to the file being whitelisted (not including the site-packages directory)
       function_name - The name of the function being whitelisted. This value can be set to None to
             act as a wildcard.
       code_fragment - The actual text from the line of code being whitelisted. This value can be
             set to None to act as a wildcard


**config/watched\_files:** This file allows developers to receive all alerts for errors related to
a particular file. They can either register to receive any exception containing the file in the
stacktrace, or to only receive alerts when the file is blamed for the exception. See file for
example.

     Fields:
       email - Email address of the watcher
       filepath - The path to the file being watched
       watch_all_errors - If true, any exception that gets reported and contains this file in it's
             traceback will be sent to the watcher. If fales, the watcher will only receive reports
             for which a line in the file was actually blamed for causing the error


**config/email\_remapping:** Remap a developer's email address that is returned by git-blame to
instead be mapped to a different email address. See file for example.

     Fields:
       remap - The email address that is being remapped
       to - The email address that should actually receive the error reports


**config/flawless.cfg:** Contains all the configuration settings for the Flawless server. To view a
list of configuration options, run the following command.

    $> flawless options










