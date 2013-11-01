from bottle import response

from unittest import TestCase
from mock import Mock, patch, MagicMock
from mock import call
from registration import SimpleRegFlow, ActivateAccountRegFlow, login_required, BaseAuthDB


class BaseRegFlowTest(TestCase):
    USERNAME = "John"
    EMAIL = "John@Doe.com"
    PWD = "Doeh!"
    PWD2 = "Duh!"
    FIRSTNAME = "JohnnyBoy"
    AGE = 22


    @patch('registration.request', remote_addr="193.432.34.3")
    def test_register_good_username_pwd(self, request_mock):
        backend = self.get_simple_reg_backend()

        result = backend.register(**{'email': self.USERNAME, 'pwd':self.PWD})

        self.assertTrue(backend.auth_db.store_user.called)
        self.assertTrue(backend.auth_db.store_user.call_args,
            call(self.USERNAME, self.PWD))

    @patch('registration.request')
    def test_random_session_id_returns_id_as_string(self, mocked_request):
        mocked_request.remote_addr = "1"
        backend = self.get_simple_reg_backend()

        session_id = backend.random_session_id

        self.assertEqual(len(session_id), 60)
        self.assertEqual(type(session_id), str)

    def get_simple_reg_backend(self, auth_db=MagicMock()):
        return SimpleRegFlow(auth_db=auth_db)


class AccountActivationBaseRegFlowTest(TestCase):
    USERNAME = "John"
    EMAIL = "John@Doe.com"
    PWD = "Doeh!"
    PWD2 = "Duh!"
    FIRSTNAME = "JohnnyBoy"
    AGE = 22

    def test_register_does_send_email(self):
        backend = self.get_simple_reg_backend()

        result = backend.register(**{'username': self.USERNAME, 'pwd': self.PWD,
            'firstname':self.FIRSTNAME, 'age':self.AGE, 'email':self.EMAIL})

        self.assertEqual(backend.auth_db.store_user.call_args[1],
            {'age': self.AGE, 'firstname': self.FIRSTNAME, 'pwd': self.PWD,
             'username': self.USERNAME, 'email': self.EMAIL})

        # TODO: Fix this
        #self.assertTrue(backend.send_account_activation_mail.called)

    def get_simple_reg_backend(self, auth_db=MagicMock()):
        return ActivateAccountRegFlow(auth_db=auth_db)


class LoginRequiredTest(TestCase):

    @patch('registration.redirect')
    def test_custom_login_required_url(self, bottle_redirect):
        reg_flow = Mock(login_required_url='/test-login')
        view = Mock()

        result = login_required(view)(reg_flow=reg_flow)

        self.assertTrue(bottle_redirect.called)
        self.assertTrue(bottle_redirect.call_args == call('/test-login'))

    @patch('registration.redirect')
    def test_when_a_user_is_not_logged_in_redirect(self, bottle_redirect):
        reg_flow = Mock()
        view = Mock()

        result = login_required(view)(reg_flow=reg_flow)

        self.assertTrue(bottle_redirect.called)


class BaseAuthDBTest(TestCase):
    PWD = "my-secret-#3pwd"

    def test_hash_method(self):
        auth_db = BaseAuthDB()
        hash = auth_db.hash(self.PWD)

        self.assertEqual(type(hash), str)
        self.assertNotEqual(hash, auth_db.hash("my-secret-different-hash"))
        self.assertNotEqual(hash, self.PWD)
        self.assertEqual(hash, auth_db.hash(self.PWD))
