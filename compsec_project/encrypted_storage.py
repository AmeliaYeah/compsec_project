from cryptography.fernet import Fernet
import json
import os

class EncryptedStorage:
	def __init__(self, filename, key_file=None):
		# get keyfile name, create it to a default if not specified
		if key_file == None:
			keyname = os.path.basename(filename).rsplit('.', 1)[0]
			key_file = f"{keyname}.key"

		# open encryption key
		try:
			with open(key_file, 'rb') as f:
				self.key = f.read()
		except FileNotFoundError:
			self.key = Fernet.generate_key()
			with open(key_file, 'wb') as f:
				f.write(self.key)
		self.cipher = Fernet(self.key)
		self.filename = filename

	def save_encrypted(self, data):
		"""Save encrypted JSON data"""
		json_data = json.dumps(data)
		encrypted = self.cipher.encrypt(json_data.encode())
		with open(self.filename, 'wb') as f:
			f.write(encrypted)

	def load_encrypted(self):
		"""Load and decrypt JSON data"""
		# default incase the file doesn't exist
		if not os.path.isfile(self.filename):
			return {}

		# open the file
		with open(self.filename, 'rb') as f:
			encrypted = f.read()
			decrypted = self.cipher.decrypt(encrypted)
		return json.loads(decrypted.decode())