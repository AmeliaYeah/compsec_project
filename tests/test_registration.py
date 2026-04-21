import requests, random
from os import urandom
from string import punctuation, ascii_lowercase, ascii_uppercase, digits

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
assert(res.status_code == 200)

# try logging in
res = s.post(f"{url}/login", data={
	"username": uname,
	"password": test_pwd_correct
})
assert(res.status_code == 200)

# now, try to login with that same user but an incorrect password
res = requests.post(f"{url}/login", data={
	"username": uname,
	"password": "obviouslyincorrectpassword"
}, verify=False)
assert(res.status_code == 403)

# try registering an account with an invalid/insecure password
def password_test(pwd, failure_text, email="valid@email.org"):
	res = requests.post(f"{url}/register", data={
		"username": urandom(10).hex(),
		"email": email,
		"password": pwd,
		"confirm_password": pwd
	}, verify=False)
	assert(failure_text in res.text)

password_test("a", "atleast 12 characters")
password_test("a"*13, "special char")

# pass the special character check
special_char = random.choice(punctuation)
password_test(special_char*13, "lowercase char")

# pass the lowercase character check
lowercase_char = random.choice(ascii_lowercase)
password_test(special_char + lowercase_char*12, "uppercase char")

# pass the uppercase character check
uppercase_char = random.choice(ascii_uppercase)
password_test(special_char + lowercase_char + uppercase_char*11, "digit")

# pass the digit check
# by now, we should have a valid password
digit_char = random.choice(digits)
password_test(special_char + lowercase_char + uppercase_char + digit_char*10, "registered")

# email check
valid_pwd = special_char+lowercase_char+uppercase_char+digit_char*10
password_test(valid_pwd, "Email format invalid", email="invalidemail")

# success!
print("Test success")