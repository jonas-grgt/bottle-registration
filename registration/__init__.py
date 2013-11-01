import base64
import hashlib
import smtplib
import inspect

from datetime import timedelta
from datetime import datetime
from threading import Thread
from email.mime.multipart import MIMEMultipart

from bottle import response
from bottle import request
from bottle import redirect
import os


def login_required(fn):
    """ Decorator that asserts a users session_id is present and valid. """
    def wrapper(*args, **kwargs):
        session_id = request.cookies.get('session_id')
        reg_flow = kwargs.get('reg_flow')

        if reg_flow.login_required_url:
            redirect_url = reg_flow.login_required_url
        else:
            redirect_url = '/login'

        if session_id:
            user = reg_flow.get_user(session_id)
            if user:
                return fn(*args, **kwargs)
            else:
                return redirect(redirect_url)
        else:
            return redirect(redirect_url)

    return wrapper


class SimpleMailer(object):
    """
    A Simple Asynchronous Mailer.

    General idea taken from bottle-crock:
        https://github.com/FedericoCeratto/bottle-cork.
    """
    def __init__(self, host='localhost',
                 registration_tmpl='',
                 pwd_reset_tmpl='',
                 *args, **kwargs):

        self._threads = []
        self.host = host
        self.registration_tmpl = registration_tmpl
        self.pwd_reset_tmpl = pwd_reset_tmpl

    def send_activation_mail(self, **context):
        self.send_mail(self.registration_tmpl, **context)

    def send_pwd_reset_mail(self, **context):
        self.send_mail(self.pwd_reset_tmpl, **context)

    def send_mail(self, template, **context):
        COMMASPACE = ', '

        template(template, **context)

        msg = MIMEMultipart()
        msg['Subject'] = context['subject']
        msg['From'] = context['from']
        msg['To'] = COMMASPACE.join(context['to'])

        thread = Thread(target=self._send, args=(context['from'], context['to'], msg))
        thread.start()
        self._threads.append(thread)

    def _send(self, sender, to, msg):
        s = smtplib.SMTP(self.host)
        s.sendmail(sender, to, msg.as_string())
        s.quit()

    def join(self):
        [th.join(5) for th in self._threads]

    def __del__(self):
        self.join()


class BaseRegFlow(object):
    """
    The mother class of all
    registration flow classes.
    """

    def __init__(self, auth_db, mailer=SimpleMailer(),
                 session_duration=5000, login_required_url='/login'):

        self.auth_db = auth_db()
        self.mailer = mailer
        self.session_duration = session_duration
        self.login_required_url = login_required_url

    @property
    def cookie_expires(self):
        return datetime.now() + timedelta(self.session_duration)

    @property
    def random_session_id(self):
        id = os.urandom(16) + request.remote_addr + datetime.now().isoformat()
        return base64.b64encode(id)

    def register(self, **user):
        return self.auth_db.store_user(**user)

    def login(self, **user):
        """
        Accepts username and pwd or
        user as parameters.
        """
        if 'user' in user:
            user = user['user']
        else:
            user = self.auth_db.get_user(**user)
        if user:
            session_id = self.random_session_id
            self.auth_db.store_session(user, session_id)

            response.set_cookie('session_id',  session_id,
                expires=self.cookie_expires, path='/', httponly=True)

        return user

    def logout(self, **user):
        response.set_cookie('session_id', 'deleted',
            path='/', expires='Thu, 01 Jan 1970 00:00:00 GMT')
        return True

    def get_user(self, session_id):
        return self.auth_db.get_user_by_session_id(session_id)

    def unregister(self, **user):
        self.auth_db.del_user(**user)

    def random_username(self):
        return "yeet"

    def random_pwd(self):
        return "yeet"


class SimpleRegFlow(BaseRegFlow):
    """

    The simplest registration flow possible.
    User registers with email and password
    and is immediately logged in.
    """

    def register(self, **user):
        email = user.get('email', False)
        pwd = user.get('pwd', self.random_pwd())

        if email:
            user = super(SimpleRegFlow, self).register(**user)

            if user: 
                self.login(**user)

            return user

        return False



class ActivateAccountRegFlow(BaseRegFlow):
    """

    The simplest registration flow possible.
    User registers with username and password
    and is immediately logged in.
    """
    def register(self, **user):
        username = user.get('username', self.random_username())
        pwd = user.get('username', self.random_pwd())

        user = super(ActivateAccountRegFlow, self).register(**user)

        if user and 'email' in user:
            self.send_account_activation_mail(user)

        return user

    def activate(self, token):
        self.auth_db.activate_user(token)

    def send_account_activation_mail(self, user):
        self.mailer.send_activation_mail()

    def send_password_reset_mail(self, user):
        self.mailer.send_pwd_reset_mail()


class RegistrationPlugin(object):
    """
    A Bottle Plugin that handles the Registration and
    Authentication flow.
    """
    def __init__(self, reg_flow, keyword='reg_flow'):
        self.reg_flow = reg_flow
        self.keyword = keyword

    def apply(self, callback, context):
        # Test if the original callback accepts a 'reg_flow' keyword.
        # Ignore it if it does not need a database handle.
        args = inspect.getargspec(context.get('callback'))[0]
        if self.keyword not in args:
            return callback

        def wrapper(*a, **ka):
            ka[self.keyword] = self.reg_flow
            return callback(*a, **ka)

        return wrapper


class BaseAuthDB(object):
    def hash(self, pwd):
        """ Simple hashing of a password """
        m = hashlib.md5()
        m.update(pwd)

        return m.hexdigest()

    def store_user(self, username, pwd, *args, **kwargs):
        """
        Received a username and password and additional user information, through kwargs.
        This method is responsible for storing the user.
        """
        raise NotImplemented()

    def del_user(self, username, pwd, *args, **kwargs):
        """
        Received a username and password and additional user information, through kwargs.
        This method is responsible for storing the user.
        """
        raise NotImplemented()

    def store_session(self, user, session_id, *args, **kwargs):
        """
        Receives a user object and session_id to be stored.

        The user object is either the same object returned in `get_user` or
        the user object passed into the Registration Flow `login` method.
        """
        raise NotImplemented()

    def del_session(self, user, session_id, *args, **kwargs):
        """
        Receives a user object and session_id to be stored.

        The user object is either the same object returned in `get_user` or
        the user object passed into the Registration Flow `login` method.
        """
        raise NotImplemented()

    def store_confirm_token(self, user, token):
        """
        Receives a user object and token to be stored.
        """
        raise NotImplemented()

    def get_user(self, **user):

        """
        Receives a user object and token to be stored.
        """
        raise NotImplemented()

    def get_user_by_session_id(self, session_id):
        raise NotImplemented()

    def get_user_by_confirm_token(self, token):
        raise NotImplemented()
