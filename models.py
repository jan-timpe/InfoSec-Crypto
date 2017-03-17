import ast, base64, hashlib, random, string
import Crypto
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256 
from Crypto.PublicKey import RSA

def generate_secret_key(size, chars=string.ascii_uppercase + string.digits):
    secret = Random.new().read(size)
    return secret
    
def hash_message(message_txt):
    message_hash = hashlib.sha256(message_txt.encode()).digest()
    return message_hash
    
def write_to_file(txt):
    f = open("messages.txt", "wb")
    f.write(txt)
    f.close()

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
        
    def rsa_encrypt(self, msg_txt, k, public_key):
        encrypted_msg = public_key.encrypt(msg_txt, k)
        return encrypted_msg[0]
    
    def rsa_decrypt(self, encrypted_msg):
        plain_msg = self.key_pair.decrypt(ast.literal_eval(str(encrypted_msg)))
        return plain_msg
        
    def rsa_sign(self, message_txt, k):
        message_hash = hash_message(message_txt)
        signed_hash = self.key_pair.sign(message_hash, k)
        return signed_hash
        
    def rsa_auth(self, message_txt, signed_hash, pub_key):
        message_hash = hash_message(message_txt)
        is_verified = pub_key.verify(message_hash, signed_hash)
        return is_verified
        
    def aes_encrypt(self, msg_txt):
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(self.shared_key, AES.MODE_CFB, init_vector)
        encrypted_msg = init_vector + cipher.encrypt(msg_txt)
        return encrypted_msg
        
    def aes_decrypt(self, ciphertext):
        init_vector = ciphertext[:AES.block_size]
        encrypted_msg = ciphertext[AES.block_size:]
        cipher = AES.new(self.shared_key, AES.MODE_CFB, init_vector)
        plain_msg = cipher.decrypt(encrypted_msg)
        return plain_msg
        
    def write_message(self, msg):
        encrypted_msg = self.aes_encrypt(msg)
        write_to_file(encrypted_msg)
        
    def read_message(self):
        encrypted_msg = read_from_file()
        plain_msg = self.aes_decrypt(encrypted_msg)
        return plain_msg.decode('utf-8')