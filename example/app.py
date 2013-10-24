import sqlite3
import bottle

from bottle import route, request, run
from bottle import redirect
from registration import BaseAuthDB, SimpleMailer, SimpleRegFlow, RegistrationPlugin, login_required


class AuthDB(BaseAuthDB):
    def store_user(self, username, pwd, *args, **kwargs):
        cursor = sqlite3.connect(':memory:').cursor()

        cursor.execute('INSERT INTO users values(\'{0}\', \'{1}\', \'{2}\')'
                            .format(username, self.hash(pwd), kwargs['email']))

        return {'email': 'jonas@geiregat.org' }

    def store_session(self, username, session_id, *args, **kwargs):
        pass

    def store_confirm_token(self, user, token):
        pass

    def update_confirm_token(self, user, token):
        pass

    def get_user(self, *args, **kwargs):
        import ipdb; ipdb.set_trace()
        return {'username':'jef'}

    def get_user_by_session_id(self, session_id):
        return self.get_user()

    def get_user_by_confirm_token(self, token):
        pass


pwd_reset_tmp = ''.join(open('pwd_reset.html', 'r').readlines())
reg_tmpl = ''.join(open('reg_tmpl.html', 'r').readlines())

mailer = SimpleMailer(registration_tmpl=reg_tmpl, pwd_reset_tmpl=pwd_reset_tmp)
reg_flow = SimpleRegFlow(auth_db=AuthDB, mailer=mailer, login_required_url='/')

registration_plugin = RegistrationPlugin(reg_flow)

bottle.install(registration_plugin)

def render_register_form():
    from bottle import SimpleTemplate
    return SimpleTemplate("""
        <form method="POST">
            <input type="text" name="email"/>
            <input type="password" name="password1"/>
            <input type="password" name="password2"/>
            <input type="submit" value="Register"/>
        </form>""").render()

def render_login_form():
    from bottle import SimpleTemplate
    return SimpleTemplate("""
        <form method="POST">
            <input type="text" name="username"/>
            <input type="password" name="password"/>
            <input type="submit" value="Login"/>
        </form>""").render()

@route('/', method='GET')
def index(reg_flow):
    from bottle import SimpleTemplate
    return SimpleTemplate("""
        <a href="/login">Login</a><br/>
        <a href="/hello">longin_required test</a>
    """).render()

@route('/register', method='GET')
def register(reg_backend):
    return render_register_form()

@route('/register', method='POST')
def register(reg_backend):
    reg_backend.register(username=request.forms.get('email'),
                         pwd=request.forms.get('password'),
                         email=request.forms.get('email'))

@route('/login', method='POST')
def post_login(reg_flow):
    user = reg_flow.login(username=request.forms.get('username'),
        pwd=request.forms.get('password'))

    if not user:
        return render_login_form()
    redirect('/users/{0}/profile'.format(user.get('username')))

@route('/login', method='GET')
def get_login(reg_flow):
    return render_login_form()

@route('/logout', method='GET')
def get_logout(reg_flow):
    reg_flow.logout()
    return "Logged out"

@route('/hello', apply=[login_required])
def hello(reg_flow):
    return "Hello authenticated world!"

@route('/users/jef/profile', apply=[login_required])
def users_profile(reg_flow):
    return "Jef's Profile"

run(host='localhost', port=8080)
