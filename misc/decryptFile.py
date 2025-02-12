#Eric Lovell = Decrypt File Functions

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

file_name = input("Please enter filename: ") #Ex. encrytion_message.txt

file_in = open(file_name, "rb")

private_key = RSA.import_key(open("private_key.pem").read())

enc_session_key, nonce, tag, ciphertext = [file_in.read(item) for item in (private_key.size_in_bytes(), 16, 16, -1)]

#Use the private key to decrypt the session key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

#Use the AES session key to decrypt the original message and print it
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
message = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(message.decode("utf-8"))
