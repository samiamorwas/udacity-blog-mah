import os
import webapp2
import jinja2
import hmac
import hashlib
import random
from string import letters

from google.appengine.ext import db

from validation import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape=True)

secret = '.a/enaiosaemfaniea;leq23m3-3qi3n'

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val
					
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	"""Called by app engine framework, to test if user is logged
		in on each page visited."""
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)
		
class User(db.Model):
	username = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = cls.all().filter('username =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					username = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

		
class MainPage(Handler):
	def get(self):
		self.write('Hi!')
		
class Signup(Handler):
	def get(self):
		self.render('signup.html')
	
	def post(self):
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')
		have_error = False
		
		params = dict(username = self.username, email = self.email)
		
		users = db.GqlQuery("select * from User order by created desc")
		
		if not valid_username(self.username):
			params['user_error'] = "Invalid username."
			have_error = True
			
		if not valid_password(self.password):
			params['pw_error'] = "Invalid password."
			have_error = True
		elif self.password != self.verify:
			params['verify_error'] = "Passwords don't match."
			have_error = True
			
		if not valid_email(self.email):
			params['email_error'] = "Invalid email."
			have_error = True
			
		if have_error:
			self.render('signup.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

class Register(Signup):
	def done(self):
		u = User.by_name(self.username)
		if u:
			msg = 'Username already taken.'
			self.render('signup.html', user_error = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/welcome')
			
class Login(Handler):
	def get(self):
		self.render('login.html')
		
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		
		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/welcome')

		else:
			self.render('login.html', login_error="Invalid login")

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/signup')
			
class Welcome(Handler):
	def get(self):
		if self.user:
			self.write('Welcome, %s' % self.user.username)
		else:
			self.redirect('/signup')
		
app = webapp2.WSGIApplication([('/', MainPage),
								('/signup', Register),
								('/welcome', Welcome),
								('/login', Login),
								('/logout', Logout)],
								debug=True)
