import ast, base64, hashlib, hmac, random, string
import Crypto
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# generates a cryptographically secure random string
def generate_secret_key(size):
    secret = Random.new().read(size)
    return secret

# hashes a string using SHA256
def hash_message(message_txt):
    message_hash = hashlib.sha256(message_txt.encode()).digest()
    return message_hash

# NOTE: writes the passed in string into a binary file
def write_to_file(txt):
    f = open("messages.txt", "wb")
    f.write(txt)
    f.close()

# NOTE: reads the contents of a binary file
def read_from_file():
    f = open("messages.txt", "rb")
    msg = f.read()
    return msg

class User:
    def __init__(self, name):
        self.name = name
        random_generator = Random.new().read
        self.key_pair = RSA.generate(1024, random_generator)

    def set_shared_key(self, key):
        self.shared_key = key

    def create_shared_key(self):
        key = generate_secret_key(AES.block_size)
        self.set_shared_key(key)

    def public_key(self):
        return self.key_pair.publickey()

    # returns a message encrypted with a specified public key
    # NOTE: k exists for legacy reasons and is effectively ignored. pass in an integer.
    def rsa_encrypt(self, msg_txt, k, public_key):
        encrypted_msg = public_key.encrypt(msg_txt, k)
        return encrypted_msg[0]

    # attempts to decrypt an encrypted message using the key pair owned by the user
    def rsa_decrypt(self, encrypted_msg):
        plain_msg = self.key_pair.decrypt(ast.literal_eval(str(encrypted_msg)))
        return plain_msg

    # signs a hash of a plain text message and returns the signature
    # NOTE: k exists for legacy reasons and is effectively ignored. pass in an integer.
    def rsa_sign(self, message_txt, k):
        message_hash = hash_message(message_txt)
        signed_hash = self.key_pair.sign(message_hash, k)
        return signed_hash

    # attempts to verify the signed message using the public key passed in as an argument
    def rsa_auth(self, message_txt, signed_hash, pub_key):
        message_hash = hash_message(message_txt)
        is_verified = pub_key.verify(message_hash, signed_hash)
        return is_verified

    # returns the message encrypted by the shared key
    # NOTE: a shared key needs to be generated and set using set_shared_key() before this method can be used
    def aes_encrypt(self, msg_txt):
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(self.shared_key, AES.MODE_CFB, init_vector)
        encrypted_msg = init_vector + cipher.encrypt(msg_txt)
        return encrypted_msg

    # attempts to decrypt a ciphertext using the shared key
    # NOTE: a shared key needs to be generated and set using set_shared_key() before this method can be used
    def aes_decrypt(self, ciphertext):
        init_vector = ciphertext[:AES.block_size]
        encrypted_msg = ciphertext[AES.block_size:]
        cipher = AES.new(self.shared_key, AES.MODE_CFB, init_vector)
        plain_msg = cipher.decrypt(encrypted_msg)
        return plain_msg

    # encrypts a message and writes the result to a binary file using write_to_file (declared at top of this file)
    def write_message(self, msg):
        encrypted_msg = self.aes_encrypt(msg)
        write_to_file(encrypted_msg)

    # attempts to decrypt the message inside of the binary file using read_from_file (declared at top of this file)
    def read_message(self):
        encrypted_msg = read_from_file()
        plain_msg = self.aes_decrypt(encrypted_msg)
        return plain_msg.decode('utf-8')

    # creates and returns a signed hash of a message using the shared key
    # NOTE: a shared key needs to be generated and set using set_shared_key() before this method can be used
    def hmac_sign(self, message_txt):
        signed_hash = hmac.new(self.shared_key, message_txt.encode(), hashlib.sha256).digest()
        return signed_hash

    # Attempts to verify a signed hash by recreating the signature with the shared key
    # NOTE: a shared key needs to be generated and set using set_shared_key() before this method can be used
    def hmac_auth(self, message_txt, signed_hash):
        computed_hash = hmac.new(self.shared_key, message_txt.encode(), hashlib.sha256).digest()
        return computed_hash == signed_hash
