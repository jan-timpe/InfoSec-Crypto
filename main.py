from models import User

def exchange_keys(sender, recipient):
    sender.create_shared_key()
    key = sender.shared_key
    enc_key = sender.rsa_encrypt(key, 32, recipient.public_key())
    recipient.set_shared_key(recipient.rsa_decrypt(enc_key))

# Perform key exchange
def test_key_exchange(sender, recipient):
    print("1. Testing Key Exchange")
    exchange_keys(sender, recipient)
    print("Sender Key: "+str(sender.shared_key))
    print("Recip. Key: "+str(recipient.shared_key))
    if sender.shared_key == recipient.shared_key:
        print("Passed!")
    else:
        print("Failed.")

# Using AES, write an encrypted message to a file to be read by another user
def test_aes_encryption(sender, recipient, message):
    print("2. Testing AES Encryption")
    ciphertext = sender.write_message(message)
    print("Original Message: "+message)
    decrypted = str(recipient.read_message())
    print("Decrypt. Message: "+decrypted)
    if decrypted == message:
        print("Passed!")
    else:
        print("Failed.")

# Using HMAC, sign a message with a shared key to be verified by another user
def test_hmac_signature(sender, recipient, message):
    print("3. Testing HMAC Authentication")
    signature = sender.hmac_sign(message)
    is_verified = recipient.hmac_auth(message, signature)
    if is_verified:
        print("Passed!")
    else:
        print("Failed.")

# Using RSA digital signatures, sign a message to be verified by another user
def test_rsa_signature(sender, recipient, message):
    print("4. Testing RSA Authentication")
    signature = sender.rsa_sign(message, 16)
    is_verified = recipient.rsa_auth(message, signature, sender.public_key())
    if is_verified:
        print("Passed!")
    else:
        print("Failed.")

# Define Users
alice = User("Alice")
bob = User("Bob")

# perform tests!
test_key_exchange(alice, bob)

msg = "this string is 25 bytes!"
test_aes_encryption(alice, bob, msg)

msg = "could be a 30 byte long string"
test_hmac_signature(alice, bob, msg)

msg = "i'll take one 40 byte long string please"
test_rsa_signature(alice, bob, msg)
