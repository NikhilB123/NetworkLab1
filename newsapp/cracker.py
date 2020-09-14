import sqlite3
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
def main():
	db = sqlite3.connect('db.sqlite3')
	cursor = db.cursor()
	cursor.execute("SELECT * from auth_user")
	passwordData = cursor.fetchall()
	commonPasswords = ["superfaketesting123"]

	for x in passwordData:
		passwordData = x[1].split('$')
		for password in commonPasswords:
			hashedPass = passwordHash(password, passwordData[2], passwordData[1])
			if hashedPass == passwordData[3]:
				print(",")
		

def passwordHash(password, passSalt, iters):
	print(passSalt)
	saltInBytes = bytes(passSalt)
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=saltInBytes,
		iterations=iters,
		backend = None
	)
	key = kdf.derive(b"my great password")
	kdf = PBKDF2HMAC(
    	algorithm=hashes.SHA256(),
    	length=32,
    	salt=saltInBytes,
    	iterations=iters,
    	backend = default_backend(),
 )
 	kdf.verify(password, key)
 	return key



if __name__ == "__main__":
	main()