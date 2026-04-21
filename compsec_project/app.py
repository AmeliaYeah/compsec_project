from flask import *
from .logger import SecurityLogger
from os import urandom, getcwd
from .uploads_management import UploadsManager
from .encrypted_storage import EncryptedStorage
from .auth import LoginManager
from functools import wraps
import hmac
import hashlib
from os import urandom
from os.path import isfile
from base64 import b64decode,b64encode
import secrets
import time
import json
import html

# logger, with a wrapper for capturing UA and IP
_security_log = SecurityLogger()
def log_event(event_type, details=None, severity='INFO'):
	_security_log.log_event(
		event_type,
		None if g.get("session_data") == None else g.session_data["username"],
		details,
		request.remote_addr,
		request.headers.get("User-Agent"),
		severity
	)

class SessionManager:
	def __init__(self, timeout=1800): # 30 minutes
		self.timeout = timeout
		self.storage = EncryptedStorage("data/sessions.json")

	def load_sessions(self):
		return self.storage.load_encrypted()

	def save_sessions(self, sessions):
		self.storage.save_encrypted(sessions)

	def create_session(self, user_id):
		"""Create new session token"""
		token = secrets.token_urlsafe(32)
		session = {
			'token': token,
			'user_id': user_id,
			'created_at': time.time(),
			'last_activity': time.time()
		}
		# Save session
		sessions = self.load_sessions()
		sessions[token] = session
		self.save_sessions(sessions)
		log_event("SESSION_CREATE", {"token": token})
		return token

	def validate_session(self, token):
		"""Check if session is valid"""
		sessions = self.load_sessions()
		if token not in sessions:
			return None
			
		session = sessions[token]

		# Check timeout
		if time.time() - session['last_activity'] > self.timeout:
			self.destroy_session(token)
			return None

		# is the user inaccessible?
		if login_manager.get_user(session["user_id"]) == None:
			self.destroy_session(token)
			return None

		session['last_activity'] = time.time()
		sessions[token] = session
		self.save_sessions(sessions)
		return session

	def destroy_session(self, token):
		"""Delete session"""
		sessions = self.load_sessions()
		if token in sessions:
			del sessions[token]
			self.save_sessions(sessions)
			log_event("SESSION_DESTROY", {"token": token})


# managers
session_manager = SessionManager()
login_manager = LoginManager()

# create the flask app
app = Flask(__name__, template_folder=f"{getcwd()}/templates")
app.secret_key = urandom(32)

@app.before_request
def load_user_session():
	token = request.cookies.get('session_token')
	if token:
		session_data = session_manager.validate_session(token)
		if session_data:
			# load the data
			data = login_manager.get_user(session_data["user_id"])
			g.session_data = data
		else:
			g.session_data = None
	else:
		g.session_data = None

def require_auth(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if g.session_data == None:
			log_event("UNAUTHORIZED_ACCESS_ATTEMPT", {"endpoint": request.path})
			return redirect('/login')
		return f(*args, **kwargs)
	return decorated_function

def require_role(role):
	def decorator(f):
		@wraps(f)
		def decorated_function(*args, **kwargs):
			if g.session_data['role'] != role:
				log_event("UNPRIVILEGED_ACCESS_ATTEMPT", {
					"endpoint": request.path,
					"role": g.session_data["role"],
					"required_role": role
				})
				abort(403) # Forbidden
			return f(*args, **kwargs)
		return decorated_function
	return decorator

@app.after_request
def set_security_headers(response):
	# Content Security Policy
	response.headers['Content-Security-Policy'] = (
		"default-src 'self'; "
		"script-src 'self' 'unsafe-inline'; " # Avoid unsafe-inline in production
		"style-src 'self' 'unsafe-inline'; "
		"img-src 'self' data:; "
		"font-src 'self'; "
		"connect-src 'self'; "
		"frame-ancestors 'none'"
	)

	# Prevent clickjacking
	response.headers['X-Frame-Options'] = 'DENY'

	# Prevent MIME type sniffing
	response.headers['X-Content-Type-Options'] = 'nosniff'

	# XSS Protection (legacy, but still useful)
	response.headers['X-XSS-Protection'] = '1; mode=block'

	# Referrer Policy
	response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

	# Permissions Policy
	response.headers['Permissions-Policy'] = (
	'geolocation=(), microphone=(), camera=()'
	)

	# HSTS (HTTP Strict Transport Security)
	response.headers['Strict-Transport-Security'] = (
	'max-age=31536000; includeSubDomains'
	)

	return response

# require https
@app.before_request
def require_https():
	if not request.is_secure and app.env != "development":
		url = request.url.replace("http://", "https://", 1)
		return redirect(url, code=301)

# login
@app.route("/login", methods=["POST", "GET"])
def login():
	# already logged in?
	if g.session_data != None:
		return redirect("/dashboard")

	# get method just returns the html page
	if request.method == "GET":
		return render_template("login.html")

	# handle post logic
	# get post data
	username = request.form.get("username")
	password = request.form.get("password")
	if not username or not password:
		flash("Please specify a username/password")
		return render_template("login.html")

	# handle authentication
	login_success, failed_login, account_locked = login_manager.login_user(username, password)
	if not login_success:
		# is this a failed login?
		if failed_login != False:
			log_event(
				'LOGIN_FAILED',
				details={'username': username, "reason": failed_login},
				severity='WARNING'
			)

		# is the account now locked?
		if account_locked:
			log_event(
				'ACCOUNT_LOCKED',
				details={'username': username},
				severity='ERROR'
			)

		# notify failed login
		flash("Invalid username/password, or locked out")
		return render_template("login.html"), 403

	# authentication successful
	log_event(
		'LOGIN_SUCCESS',
		details={'username': username}
	)

	# set cookie and redirect
	token = session_manager.create_session(username)
	response = make_response(redirect('/dashboard'))
	response.set_cookie(
		'session_token',
		token,
		httponly=True, # Prevent JavaScript access
		secure=True, # HTTPS only
		samesite='Strict', # CSRF protection
		max_age=1800 # 30 minutes
	)

	# log session creation
	g.session_data = {"username": username}
	return response

@app.route("/dashboard", methods=["GET"])
@require_auth
def dashboard():
	# if we're admin, get the users
	users = None
	if g.session_data["role"] == "admin":
		users = login_manager.list_users()

	# get all documents and return the dashboard
	uploads = UploadsManager(g.session_data)
	return render_template("dashboard.html", documents=uploads.get_all_documents(), users=users)

@app.route("/register", methods=["GET", "POST"])
def register():
	# already logged in?
	if g.session_data != None:
		return redirect("/dashboard")

	# if GET, just return the page
	if request.method == "GET":
		return render_template("register.html")

	# get values
	username = request.form.get("username")
	email = request.form.get("email")
	password = request.form.get("password")
	confirm = request.form.get("confirm_password")
	if not username or not email or not password or not confirm:
		flash("Username, email, or password/confirmation not specified")
		return render_template("register.html")

	# verify password and confirmation password are identical
	if password != confirm:
		flash("Password and confirmation password do not match")
		return render_template("register.html")

	# try registering
	success, result = login_manager.register_user(username, email, password)
	if not success:
		flash(result)
		return render_template("register.html"), 400

	# log if success
	log_event(
		'REGISTRATION_SUCCESS',
		{'username': username},
	)

	# redirect to login
	flash(result)
	return render_template("register.html")

@app.route("/logout", methods=["POST"])
@require_auth
def logout():
	# delete cookie and destroy session
	resp = make_response(redirect("/login"))

	# destroy the session token
	token = request.cookies.get("session_token")
	session_manager.destroy_session(token)

	# mark the token as no longer valid
	resp.delete_cookie("session_token")
	return resp

@app.route("/")
def main():
	return redirect("/login" if g.session_data == None else "/dashboard")

@app.route("/document/delete/<doc_id>", methods=["POST"])
@require_auth
def delete_document(doc_id):
	# get the document
	uploads = UploadsManager(g.session_data)
	doc, access_denied = uploads.get_document(doc_id)
	if not doc:
		if access_denied:
			log_event("UNAUTHORIZED_DOCUMENT_DELETE", {
				"doc_id": doc_id
			}, severity="WARNING")
		return redirect("/")

	# delete the document
	uploads.delete_document(doc_id)
	log_event("AUTHORIZED_DOCUMENT_DELETE", {
		"doc_id": doc_id,
		"doc_owner": doc["owner"],
		"sha256": hashlib.sha256(b64decode(doc["data"])).hexdigest()
	})

	# redirect to dashboard
	return redirect("/dashboard")

@app.route("/document/edit/<doc_id>", methods=["POST"])
@require_auth
def edit_document(doc_id):
	# get the document
	uploads = UploadsManager(g.session_data)
	doc, access_denied = uploads.get_document(doc_id)
	if not doc:
		if access_denied:
			log_event("UNAUTHORIZED_DOCUMENT_EDIT", {
				"doc_id": doc_id
			}, severity="WARNING")
		return redirect("/")

	# edit the document
	res = uploads.edit_document(
		doc_id,
		new_name=request.form.get("name"),
		new_data=request.files.get("file").read()
	)

	# log, then display for user
	log_event("AUTHORIZED_DOCUMENT_EDIT", {"doc_id": doc_id}|res)
	if "name" in res:
		flash(f"Changed {res['old_name']} to {res['name']}")
	if "data" in res:
		flash(f"File hash changed from {res['old_data']} to {res['data']}")
	return redirect("/dashboard")

@app.route("/document/<doc_id>", methods=["GET"])
def get_document(doc_id):
	# compute the correct share code
	# if the share code is illegitamate, then mark it as none (invalid)
	# mark the attempted sharecode
	correct_code = hmac.new(app.secret_key, doc_id.encode("utf-8"), hashlib.sha256).hexdigest()
	share_code = request.args.get("share_code")
	invalid_share_code = share_code != correct_code
	forged_code = None
	if invalid_share_code:
		forged_code = share_code
		share_code = None

	# get the document
	uploads = UploadsManager(g.session_data)
	doc, access_denied = uploads.get_document(doc_id, share_code != None)
	if not doc:
		if access_denied:
			log_event("UNAUTHORIZED_DOCUMENT_ACCESS", {
				"attempted_sharecode": forged_code,
				"doc_id": doc_id
			}, severity="WARNING")
		return redirect("/")

	# note privileged document access
	is_download = request.args.get("raw") == "true"
	log_event("AUTHORIZED_DOCUMENT_ACCESS", {
		"sharecode": share_code,
		"doc_id": doc_id,
		"doc_owner": doc["owner"],
		"action": "view" if not is_download else "download"
	})

	# if we specified "raw", then show the raw document contents
	if is_download:
		resp = make_response(b64decode(doc["data"]))
		resp.headers.set("Content-Type", "application/octet-stream")
		return resp

	# render the template
	# we're using safe on the urls, make sure to html escape the user-supplied sharecode
	# the share code should just be hex
	# doc_id should have been a valid doc_id to get here
	if share_code:
		share_code = html.escape(share_code)
	doc = {
		"name": doc["name"],
		"url": url_for('get_document', doc_id=doc_id, raw="true", share_code=share_code),
		"share_url": url_for("get_document", doc_id=doc_id, share_code=correct_code, _external=True)
	}
	return render_template("document.html", document=doc)

@app.route("/upload", methods=["GET", "POST"])
@require_auth
def upload_document():
	if request.method == "GET":
		return render_template("upload.html")

	# get the file and the name
	doc_file = request.files.get("file")
	doc_name = request.form.get("name")
	if not doc_file or not doc_name:
		flash("You must specify your document and your document name", "failure")
		return render_template("upload.html")

	# get the upload manager and set the document
	uploads = UploadsManager(g.session_data)
	doc_data = doc_file.read()
	doc_id = uploads.upload_document(b64encode(doc_data).decode("ascii"), doc_name)

	# log file upload
	log_event("FILE_UPLOAD", {
		"doc_name": doc_name,
		"doc_id": doc_id,
		"sha256": hashlib.sha256(doc_data).hexdigest()
	})

	# redirect
	return redirect(url_for("get_document", doc_id=doc_id))

@app.route("/admin/update_role", methods=["POST"])
@require_auth
@require_role("admin")
def update_user_role():
	# get username and role
	username = request.form.get("username")
	role = request.form.get("role")
	if not username or not role:
		flash("You must specify username and their target role")
		return redirect("/dashboard")

	# verify role
	if role != "admin" and role != "user":
		flash(f"Role must be admin or user; {role} isn't a valid role")
		return redirect("/dashboard")

	# set role
	res = login_manager.change_user(username, role=role)
	if res == None:
		flash("Error while changing role (maybe user doesn't exist?)")
		return redirect("/dashboard")

	# notify success
	flash(f"{username} is now {res['role']}", "success")
	log_event("ADMIN_ROLE_CHANGED", {"user": username, "newrole": res['role']})
	return redirect("/dashboard")

@app.route("/admin/change_password", methods=["POST"])
@require_auth
@require_role("admin")
def change_pwd():
	# get username and password
	username = request.form.get("username")
	passwd = request.form.get("new_password")
	if not username or not passwd:
		flash("You must specify username and their target password")
		return redirect("/dashboard")

	# set password
	res = login_manager.change_user(username, password=passwd)
	if res == None:
		flash("Error while changing password (maybe user doesn't exist?)")
		return redirect("/dashboard")

	# notify success
	flash(f"{username} password changed", "success")
	log_event("ADMIN_PASSWORD_CHANGED", {"user": username})
	return redirect("/dashboard")

@app.route("/admin/delete_user", methods=["POST"])
@require_auth
@require_role("admin")
def delete_user():
	# get username
	username = request.form.get("username")
	if not username:
		flash("You must specify username")
		return redirect("/dashboard")

	# delete the user
	if not login_manager.delete_user(username):
		flash("Couldn't delete user (maybe they don't exist?)")
		return redirect("/dashboard")

	# notify success
	flash(f"{username} deleted", "success")
	log_event("ADMIN_USER_DELETED", {"user": username})
	return redirect("/dashboard")

if __name__ == "__main__":
	# create admin user, only if users.json doesn't exist
	if not isfile("data/users.json"):
		print(f"Initialized admin user 'admin' with the password || {login_manager.create_admin_user()} ||")
		print("It is recommended to memorize this password and then clear it from this terminal and anywhere else.")

	# run the site
	app.run(ssl_context=("cert.pem", "key.pem"), host="0.0.0.0", port=5000, debug=False)