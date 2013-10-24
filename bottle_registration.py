import smtplib
import uuid
import inspect
import OpenSSL

from datetime import timedelta
from datetime import datetime
from threading import Thread
from email.mime.multipart import MIMEMultipart

from bottle import response
from bottle import request
from bottle import redirect


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
        return str(uuid.UUID(bytes = OpenSSL.rand.bytes(16))).replace('-', '')

    def register(self, username, pwd, **kwargs):
        return self.auth_db.store_user(username, pwd, **kwargs)

    def login(self, *args, **kwargs):
        """
        Accepts username and pwd or
        user as parameters.
        """
        if 'user' in kwargs:
            user = kwargs['user']
        else:
            user = self.auth_db.get_user(username=kwargs['username'], pwd=kwargs['pwd'])
        if user:
            session_id = self.random_session_id
            self.auth_db.store_session(user, session_id)

            response.set_cookie('session_id',  session_id,
                expires=self.cookie_expires, path='/', httponly=True)

        return user

    def logout(self, *args, **kwargs):
        response.set_cookie('session_id', 'deleted',
            path='/', expires='Thu, 01 Jan 1970 00:00:00 GMT')
        return True

    def get_user(self, session_id):
        return self.auth_db.get_user_by_session_id(session_id)

    def unregister(self, username, password):
        self.auth_db.remove_user(username, password)


class SimpleRegFlow(BaseRegFlow):
    """

    The simplest registration flow possible.
    User registers with username and password
    and is immediately logged in.
    """

    def register(self, username, pwd, **kwargs):
        user = super(SimpleRegFlow, self).register(username, pwd, **kwargs)
        return self.login(username=username, pwd=pwd)


class ActivateAccountRegFlow(BaseRegFlow):
    """

    The simplest registration flow possible.
    User registers with username and password
    and is immediately logged in.
    """
    def register(self, username, pwd, **kwargs):
        user = super(ActivateAccountRegFlow, self).register(username, pwd, **kwargs)
        if user and 'email' in kwargs:
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
        pass

    def store_user(self, username, pwd, *args, **kwargs):
        raise NotImplemented()

    def store_session(self, username, session_id, *args, **kwargs):
        raise NotImplemented()

    def store_confirm_token(self, user, token):
        raise NotImplemented()

    def get_user(self, *args, **kwargs):
        raise NotImplemented()

    def get_user_by_session_id(self, session_id):
        raise NotImplemented()

    def get_user_by_confirm_token(self, token):
        raise NotImplemented()
