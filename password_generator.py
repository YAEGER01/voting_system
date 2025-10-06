from werkzeug.security import generate_password_hash

password = "sisadmin123"
hash = generate_password_hash(password, method="scrypt")
print(hash)
