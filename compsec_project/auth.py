from functools import wraps
import bcrypt
import json
import time
import re
import random
from string import punctuation, ascii_uppercase, ascii_lowercase, digits, ascii_letters
from datetime import datetime, timedelta
from .encrypted_storage import EncryptedStorage

class LoginManager():
	users_path = "data/users.json"
	def __init__(self):
		self.storage = EncryptedStorage("data/users.json")

	def check_locked(self, data, username):
		user = data[username]
		if user["locked_until"] != None:
			# are we locked out?
			if datetime.utcnow() < datetime.fromisoformat(user["locked_until"]):
				return True
			else:
				user["locked_until"] = None
				user["failed_attempts"] = 0
				self.storage.save_encrypted(data)

		# we aren't locked out
		return False

	def list_users(self):
		users = []
		data = self.storage.load_encrypted()
		for username,user in data.items():
			users.append(user | {"username": username})
		return users

	def get_user(self, username):
		data = self.storage.load_encrypted()
		res = data.get(username)
		if res == None:
			return None

		# if the user is locked, abort
		if self.check_locked(data, username):
			return None

		# set the username, then return
		return {
			"username": username,
			"email": res["email"],
			"role": res["role"]
		}

	def validate_username(self, username):
		if len(username) < 3 or len(username) > 20:
			return "Username must be between 3-20 characters."
		if not bool(re.fullmatch(r'\w+', username)):
			return "Username must be alphanumeric + underscores only."

		# check if username exists
		data = self.storage.load_encrypted()
		if username in data:
			return "Username already exists!"
		return True

	def validate_email(self, email):
		pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
		if re.fullmatch(pattern, email) is None:
			return "Email format invalid"
		return True

	def validate_password_strength(self, password):
		if len(password) < 12:
			return "Password must be atleast 12 characters"

		special = lowercase = uppercase = number = None
		for c in password:
			if c in punctuation:
				special = True
			if c in ascii_lowercase:
				lowercase = True
			if c in ascii_uppercase:
				uppercase = True
			if c in digits:
				number = True

		msg = "Password must have atleast 1 "
		if not special:
			return msg + "special character"
		if not lowercase:
			return msg + "lowercase character"
		if not uppercase:
			return msg + "uppercase character"
		if not number:
			return msg + "digit"
		return True

	def get_pwd_hash(self, password):
		salt = bcrypt.gensalt(rounds=12)
		hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
		return hashed.decode("utf-8")

	def generate_user_entry(self, username, email, password, role="user"):
		data = self.storage.load_encrypted()
		data[username] = {
			"email": email,
			"password_hash": self.get_pwd_hash(password),
			"created_at": time.time(),
			"role": role,
			"failed_attempts": 0,
			"locked_until": None
		}
		self.storage.save_encrypted(data)

	def change_user(self, username, role=None, password=None):
		data = self.storage.load_encrypted()
		user = data.get(username)
		if user == None:
			return None

		if role:
			user["role"] = role

		if password:
			user["password_hash"] = self.get_pwd_hash(password)

		# save, and then return the user data
		self.storage.save_encrypted(data)
		return user

	def delete_user(self, username):
		data = self.storage.load_encrypted()
		user = data.get(username)
		if user == None:
			return False

		del data[username]
		self.storage.save_encrypted(data)
		return True

	def create_admin_user(self):
		admin_pwd = "".join(random.choices(punctuation+ascii_letters+digits, k=48))
		self.generate_user_entry("admin", "admin@securesite", admin_pwd, role="admin")
		return admin_pwd

	def register_user(self, username, email, password):
		# Validate email
		res = self.validate_email(email)
		if res != True:
			return False, res

		# Validate username
		res = self.validate_username(username)
		if res != True:
			return False, res

		# Validate password
		res = self.validate_password_strength(password)
		if res != True:
			return False, res

		# Store user entry
		self.generate_user_entry(username, email, password)
		return True, f"User '{username}' registered!"

	# returns (login_success, failure_reason, account_locked)
	# first is if user actually can be granted a session
	# second is a login failure occured and WHY it occured
	# third is if the account got locked from a last invalid login attempt
	def login_user(self, username, password):
		# get the data
		data = self.storage.load_encrypted()

		# verify username exists
		if username not in data:
			return False, False, False

		# get the username
		user = data[username]

		# check lockout
		if self.check_locked(data, username):
			return False, "account is locked", False

		# verify password is correct
		if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
			# add to failed attempts; lock if reached maximum
			user["failed_attempts"] += 1
			locked = False
			if user["failed_attempts"] >= 5:
				# calculate lockout time
				lockout_time = datetime.utcnow() + timedelta(minutes=15)
				user["locked_until"] = lockout_time.isoformat()
				locked = True
			
			# deny access
			# save data since we're modifying failed attempts
			self.storage.save_encrypted(data)
			return False, "password incorrect", locked

		# password is correct, allow login
		return True, False, False