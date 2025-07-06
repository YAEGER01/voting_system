from werkzeug.security import generate_password_hash

password = "PAssowr"
hash = generate_password_hash(password, method='scrypt')
print(hash)
