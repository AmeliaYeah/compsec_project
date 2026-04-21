import requests, random
from os import urandom

# disable warnings
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# params (self-signed cert ignore)
url = "https://localhost:5000"
s = requests.session()
s.verify = False

# try registering with a password that passes the test cases
uname = urandom(10).hex()
test_pwd_correct = "1aAbC@@$102951"
res = s.post(f"{url}/register", data={
	"username": uname,
	"email": "test@test.org",
	"password": test_pwd_correct,
	"confirm_password": test_pwd_correct
})

# try logging in
res = s.post(f"{url}/login", data={
	"username": uname,
	"password": test_pwd_correct
})

# create an example document
# use lfi as an example to prove no lfi
example_document = b"blahh"
document_name = "../../lfi"

# upload it
res = s.post(f"{url}/upload", files={
	"file": ("something", example_document)
}, data={"name": document_name}, allow_redirects=True)
assert(res.status_code == 200)

# get the URL to download this raw
document_url = res.url

# get the share url
share_code = res.text[res.text.index("share_code"):]
share_code = share_code[:share_code.index("\"")]
share_code = share_code[share_code.index("share_code=")+len("share_code="):]
print(f"Share code: {share_code}")

# download the document and see if it's our example document
res = s.get(f"{res.url}?raw=true").content
assert(res == example_document)

# now, check if we can download as a guest with/without the share code
def guest_download_sharecode(sharecode, should_fail):
	# if it fails and we're unauthorized, we'll be redirected to "/"
	#	which means we'll be redirected to the login screen
	# if it doesn't fail, we'll stay on the target URL, able to see the document
	target_url = f"{document_url}?share_code={sharecode}"
	res = requests.get(target_url, verify=False, allow_redirects=True)
	assert(res.url == (f"{url}/login" if should_fail else target_url))

guest_download_sharecode(share_code, False)
guest_download_sharecode("invalidsharecode", True)

print("Tests succeeded!")