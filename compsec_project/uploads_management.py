from .encrypted_storage import EncryptedStorage
from os import urandom
from hashlib import sha256
from base64 import b64decode,b64encode

class UploadsManager():
	def __init__(self, session_data):
		self.storage = EncryptedStorage("data/uploads.json")
		self.session_data = session_data

	# returns (document, access_denied)
	# access_denied means we were denied access to the document BECAUSE of perm reasons
	def get_document(self, doc_id, is_shared=False):
		data = self.storage.load_encrypted()
		doc = data.get(doc_id)
		if doc == None:
			return None, False

		# if we have shared access, return the doc without perm check
		if is_shared:
			return doc, False

		# if the session data is not set and it's unshared, then deny
		if self.session_data == None:
			return None, True

		# admin can see all docs
		if self.session_data["role"] == "admin":
			return doc, False

		# check if we own the document
		if doc["owner"] != self.session_data["username"]:
			return None, True

		# return the document
		return doc, False

	# get all the documents which we can access
	def get_all_documents(self):
		data = self.storage.load_encrypted()
		docs = []
		for doc_id,doc_data in data.items():
			# if we aren't admin and don't own the document, don't count this one
			if self.session_data["role"] != "admin" and doc_data["owner"] != self.session_data["username"]:
				continue

			# add the document
			docs.append(doc_data | {"id": doc_id})

		# return the documents
		return docs

	def upload_document(self, raw_data, doc_name):
		data = self.storage.load_encrypted()

		doc_id = urandom(16).hex()
		data[doc_id] = {
			"owner": self.session_data["username"],
			"data": raw_data,
			"name": doc_name
		}

		self.storage.save_encrypted(data)
		return doc_id

	def delete_document(self, doc_id):
		data = self.storage.load_encrypted()
		del data[doc_id]
		self.storage.save_encrypted(data)

	def edit_document(self, doc_id, new_name=None, new_data=None):
		# get the document
		data = self.storage.load_encrypted()
		doc = data.get(doc_id)

		# update the document
		return_dat = {}
		if new_name:
			return_dat["name"] = new_name
			return_dat["old_name"] = doc["name"]
			doc["name"] = new_name
		if new_data:
			return_dat["data"] = sha256(new_data).hexdigest()
			return_dat["old_data"] = sha256(b64decode(doc["data"])).hexdigest()
			doc["data"] = b64encode(new_data).decode("ascii")

		# save the document, returned the changed stuff
		self.storage.save_encrypted(data)
		return return_dat