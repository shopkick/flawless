Flawless
========

Flawless is a simple Python framework developed at shopkick for detecting bugs in a production
environment. Flawless traps exceptions and then sends an email to the developer responsible
for causing the exception. Flawless integrates with git and uses git-blame to determine which
developer to email.


Project website: [http://shopkick.github.com/flawless/](http://shopkick.github.com/flawless/)


Why You Should Use Flawless
---------------------------

  * Only sends 1 email per line of code. Even if a particular line of code causes thousands of
    exceptions, only one email will be sent.

  * Only emails 1 developer. Flawless uses git-blame to figure out which developer is responsible
    for a particular exception, and will only email that developer.

  * Flawless logs the values of every variable in the stack frame at the time the exception
    occurred. This makes debugging ten times faster.

  * Don't report exceptions in old code. If you set report\_only\_after\_minimum\_date, then
    Flawless will only report exceptions caused by code modified after
    report\_only\_after\_minimum\_date.

  * Don't alert on library code. You can mark certain files/functions as library code, and when an
    exception originates in those files/functions, the caller will be blamed for the error instead
    of the library code.


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
you can wrap particular functions or entire classes by using flawless.client.decorators. View the
examples directory for some actual code examples.


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


Example Email
---------------------

<pre><code><b>Traceback (most recent call last):</b>
  File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/flawless-0.1.4-py2.6.egg/flawless/client/middleware.py", line 34, in __call__
     return self.app(environ, start_response) 
  File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/Beaker-1.6.4-py2.6.egg/beaker/middleware.py", line 73, in __call__
     return self.app(environ, start_response) 
  File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/apps/shopkick/pylons/lib/json_api.py", line 66, in wrapped
     return func(obj, **new_kwargs) 
  File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/apps/shopkick/pylons/controllers/user.py", line 535, in create_web_registration
     return handler.run() # Returns json string 
  File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/apps/shopkick/pylons/controllers/user.py", line 2190, in run
     session.commit() 
  File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/SQLAlchemy-0.7.1-py2.6-linux-x86_64.egg/sqlalchemy/orm/session.py", line 617, in commit
     self.transaction.commit() 
  File "/build/bdist.linux-x86_64/egg/MySQLdb/cursors.py", line 173, in execute
     self.errorhandler(self, exc, value) 
  File "/build/bdist.linux-x86_64/egg/MySQLdb/connections.py", line 36, in defaulterrorhandler
     raise errorclass, errorvalue 
IntegrityError('(IntegrityError) (1062, "Duplicate entry \'10229602058\' for key \'PRIMARY\'")',)


<b>Stack Frame:</b>
  <b>File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/apps/shopkick/pylons/lib/json_api.py", line 66, in wrapped</b>
    arg='self'
    func=<function create_web_registration at 0x7f6c2acf35f0>
    kwargs={'pylons': <pylons.util.PylonsContext object at 0x7f6a5c800190>, 'start_response': <function repl_start_response at 0x7f6a5c80fed8>, 'controller': u'user', 'environ': {'routes.route': <routes.route.Route object at 0x7f6c2a61b850>, 'mod_wsgi.listener_...
    new_kwargs={}
    obj=<apps.shopkick.pylons.controllers.user.UserController object at 0x7f6a5c800110>
    self.request_info=JsonRequestInfo(logging_details_field_name='create_web_registration_request_details', web_authentication_type=0, logging_request_type=71, request_path='/shopkick/v1/user/create_web_registration')
  <b>File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/apps/shopkick/pylons/controllers/user.py", line 535, in create_web_registration</b>
    client_platform=2
    download_url_type=''
    email=None
    error_manager=<apps.shopkick.pylons.lib.web_registration_helpers.ErrorManager object at 0x7f6a5c800150>
    facebook_access_token=None
    first_name=None
    gift_manager=<apps.shopkick.pylons.lib.gifts.GiftManager object at 0x7f6a5c800450>
    gift_token=''
    handler=<apps.shopkick.pylons.controllers.user.CreateWebRegistrationHandler object at 0x7f6a5c800f90>
    invite_token=None
    self._pylons_log_debug=False
    self.start_response=<function repl_start_response at 0x7f6a5c80fed8>
    user_service=<lib.thrift.utils.persistent_thrift_service.ThriftService object at 0x7f6c2a1f2410>
    zip_code=None
  <b>File "/services/shopkick_pylons/shopkick_pylons-current/py/lib/python2.6/site-packages/apps/shopkick/pylons/controllers/user.py", line 2190, in run</b>
    b_resp=CreateWebRegistrationResponse(status=0, web_registration_id=10229602058)
    create_web_registered_user=<function create_web_registered_user at 0x7f6a80faf9b0>
    gift_resp=None
    is_full_registration=False
    is_new_web_registration=True
    record=WebregRepingRecord(webreg_user_id=10229602058, encrypted_webreg_user_id='KIOTYQ97P7H8', client_platform=2, reping_status=0, created=None)
    self.client_platform=2
    self.download_url_type=''
    self.email=None
    self.error_manager=<apps.shopkick.pylons.lib.web_registration_helpers.ErrorManager object at 0x7f6a5c800150>
    self.facebook_access_token=None
    self.facebook_access_token_func=<function _facebook_user_id_from_access_token at 0x7f6c2ac719b0>
    self.facebook_user_id=None
    web_registration_id='KIOTYQ97P7H8'


<b>Additional Information:</b>
POST /shopkick/v1/user/create_web_registration HTTP/1.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Charset: utf-8, iso-8859-1, utf-16, *;q=0.7
Accept-Encoding: gzip
Accept-Language: en-us,en;q=0.9
Cache-Control: max-age=43200
Connection: close
Content-Length: -1
Content-Type: application/x-www-form-urlencoded
Cookie: session_id=1E9DTWDVCQ7M8; __utma=151718139.482813466.1384371861.1384371861.1384832848.2; __utmb=151718139.2.9.1384832848; __utmc=151718139;
Host: app.shopkick.com
Origin: http://app.shopkick.com
Referer: http://app.shopkick.com/download_page?launch_reg=1
User-Agent: Mozilla/5.0 (Linux; U; Android 2.2.2; en-us; VM670 Build/FRG83G) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1
X-Forwarded-For: 255.87.109.255
X-Real-Ip: 255.87.109.255
X-Requested-With: XMLHttpRequest

gift_token=&download_url_type=&gift_token=
</code></pre>

Server User Interface
---------------------

**/get\_weekly\_error\_report** - Shows all errors that happened this week. ses a leaderboard style
format to show which developer is responsible for causing the most errors this week.

     Parameters:
       timestamp - (optional) Specify which week you want to view. Default is the current week.
       include_known_errors - (optional) Include errors from config/known_errors. Default is False.
       include_modified_before_min_date - (optional) Include errors originating in code modified
       before flawless.cfg option "report_only_after_minimum_date". Default is False.

**/check\_health** - Check if the server is up and running. Also displays server's configuration
parameters

**/add\_known\_error** - Webpage in which you can whitelist errors

**/view\_traceback** - View the most recent traceback for a particular error

     Parameters:
       filename - (required) Specify the filename in which the error occurred
       function_name - (required) Specify the name of the function in which the error occurred
       line_number - (required) Specify the line number on which the error occurred
       text - (required) Specify the full text that appears on line_number
       timestamp - (optional) Specify which week you want to view. Default is the current week.











