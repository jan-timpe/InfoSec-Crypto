from models import User

def exchange_keys(sender, recipient):
    sender.create_shared_key()
    key = sender.shared_key
    enc_key = sender.rsa_encrypt(key, 32, recipient.public_key())
    recipient.set_shared_key(recipient.rsa_decrypt(enc_key))

# Define Users
alice = User("Alice")
bob = User("Bob")

# Perform key exchange
exchange_keys(alice, bob)
print("1. "+str(alice.shared_key == bob.shared_key)) # verify that the key exchange was successful

msg = "bite my shiny metal ass"

# Using AES, write an encrypted message to a file to be read by another user
ciphertext = alice.write_message(msg)
print("2. "+str(str(bob.read_message()) == msg))

# Using HMAC, sign a message with a shared key to be verified by another user
signature = alice.hmac_sign(msg)
print("3. "+str(bob.hmac_auth(msg, signature)))

# Using RSA digital signatures, sign a message to be verified by another user
signature = alice.rsa_sign(msg, 16)
print("4. "+str(bob.rsa_auth(msg, signature, alice.public_key())))