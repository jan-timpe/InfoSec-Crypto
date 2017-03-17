from models import User
    
def exchange_keys(sender, recipient):
    sender.create_shared_key()
    key = sender.shared_key
    # print(key) # debug
    # key = "this is a message"
    enc_key = sender.rsa_encrypt(key, 32, recipient.public_key())
    recipient.set_shared_key(recipient.rsa_decrypt(enc_key))
    # print(recipient.shared_key) # debug

alice = User("Alice")
bob = User("Bob")

exchange_keys(alice, bob)

msg = "bite my shiny metal ass"

# ciphertext = alice.write_message(msg)
# print("MSG: "+str(bob.read_message()))


# signature = alice.rsa_sign(msg, 16)
# if bob.rsa_auth(msg, signature, alice.public_key()):
#     print("passed")
# else:
#     print("failed")

# signature = alice.hmac_sign(msg)
# if bob.hmac_auth(msg, signature):
#     print("passed")
# else:
#     print("failed")