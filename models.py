import ast, base64, hashlib, random, string
import Crypto
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256 
from Crypto.PublicKey import RSA

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-s[-1]]

def generate_secret_key(size, chars=string.ascii_uppercase + string.digits):
    secret = Random.new().read(size)
    return secret
    
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
        # self.shared_key = hashlib.sha256(key).digest()
        
    def create_shared_key(self):
        key = generate_secret_key(16)
        self.set_shared_key(key)
            
    def public_key(self):
        return self.key_pair.publickey()
        
    def rsa_encrypt(self, msg_txt, k, public_key):
        encrypted_msg = public_key.encrypt(msg_txt, k)
        # print("ENC: "+str(encrypted_msg[0])) # debug
        return encrypted_msg[0]
    
    def rsa_decrypt(self, encrypted_msg):
        plain_msg = self.key_pair.decrypt(ast.literal_eval(str(encrypted_msg)))
        # print("DEC: "+str(plain_msg)) # debug
        return plain_msg
        
    def aes_encrypt(self, msg_txt):
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(self.shared_key, AES.MODE_CFB, init_vector)
        # encrypted_msg = cipher.encrypt(pad(msg_txt))
        encrypted_msg = init_vector + cipher.encrypt(msg_txt)
        print("ENC: "+str(encrypted_msg))
        return encrypted_msg
        
    def aes_decrypt(self, ciphertext):
        init_vector = ciphertext[:BS]
        encrypted_msg = ciphertext[BS:]
        cipher = AES.new(self.shared_key, AES.MODE_CFB, init_vector)
        # plain_msg = unpad(cipher.decrypt(encrypted_msg))
        plain_msg = cipher.decrypt(encrypted_msg)
        print("DEC: "+str(plain_msg))
        return plain_msg
        
    def write_message(self, msg):
        encrypted_msg = self.aes_encrypt(msg)
        # write_to_file(base64.b64encode(encrypted_msg))
        write_to_file(encrypted_msg)
        print("WRITE: "+str(encrypted_msg)) # debug
        
    def read_message(self):
        # line = base64.b64decode(read_from_file())
        encrypted_msg = read_from_file()
        print("READ: " + str(encrypted_msg))
        plain_msg = self.aes_decrypt(encrypted_msg)
        return plain_msg.decode('utf-8', errors="ignore")