#!\usr\bin\python3 
# python = 3.6.13  


from secrets import token_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

import sqlite3
import os
import re
import shutil
# plain_text = "abcdefghijklmnopqrstuvwxyz"

# key = ""
# iv = ""
# aes_cipher = Cipher(algorithm=algorithms.AES(), mode=modes.GCM())
class RSA_secure:
    def __init__(self, email):

        self.email = email
        self.encrypt_ext = ".encrypted"
        self.columns = {"email":0, "public_key":1, "private_key":2}
        # create database for users
        conn = sqlite3.connect('userdb.sqlite')
        self.cur = conn.cursor()

        self.cur.execute('''CREATE TABLE IF NOT EXISTS Users (email TEXT, public_key TEXT, private_key TEXT)''')
        self.cur.execute('SELECT * FROM Users WHERE email = ? ', (email,))
        row = self.cur.fetchone()
        if row is None:
            # generate key
            key = RSA.generate(2048)

            # write private key to file
            self.private_key = key.export_key()

            # write public key to file
            self.public_key = key.publickey().export_key()

            self.cur.execute('''INSERT INTO Users (email, public_key, private_key)
                VALUES (?, ?, ?)''', (email, self.public_key, self.private_key))

            print("[INFO] New Public & Private Keys Generated for User {}...".format(email))
        else:
            # Load existing keys
            self.public_key = RSA.import_key(row[self.columns["public_key"]])
            self.private_key = RSA.import_key(row[self.columns["private_key"]])
            print("[INFO] Loading Public & Private Keys for User {}...".format(row[self.columns["email"]]))

        self.backup_path = email+"_backup/"
        self.restore_path = email+"_restore/"
        os.makedirs(self.restore_path, exist_ok=True)
        os.makedirs(self.backup_path, exist_ok=True)

        conn.commit()
        pass

    def _encrypt_file(self, path):

        # read the 
        fp_plain = open(path, 'rb')
        plain_fp_content = fp_plain.read()

        fp_cipher = open(self.backup_path + path + self.encrypt_ext, 'wb')

        # plain = plain_fp_content.encode('utf-8')
        aes_key = token_bytes(32)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        enc_session_key = cipher_rsa.encrypt(aes_key)
        
        aes_cipher = AES.new(aes_key, AES.MODE_GCM)
        (cipher, tag) = aes_cipher.encrypt_and_digest(plain_fp_content)
        [ fp_cipher.write(x) for x in (enc_session_key, aes_cipher.nonce, tag, cipher) ]

        fp_cipher.close()
        fp_plain.close()
        pass

    def _decrypt_file(self, path):

        encrypted_file = path
        cipher_file = open(encrypted_file, 'rb')

        plain_file = self.restore_path+".".join(path.split(".")[:-1])

        fp_plain_restore = open(plain_file, 'wb')
        private_key = self.private_key

        enc_session_key, nonce, tag, ciphertext = [ cipher_file.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        aes_cipher = AES.new(session_key, AES.MODE_GCM,nonce=nonce)
        decrypted = aes_cipher.decrypt_and_verify(ciphertext,tag)
        fp_plain_restore.write(decrypted)

        fp_plain_restore.close()
        cipher_file.close()
        return plain_file
        pass

    def _encrypt_folder(self, path):
        
        # zip
        output_filename = path
        shutil.make_archive(output_filename, 'zip', path)
        path = output_filename+".zip"

        os.rmdir(path)
        self._encrypt_file(path=path)
        # fp = open(path, "rb")
        # plain_content = fp.read()
        
        pass

    def _decrypt_folder(self, path):
        restore_path = self._decrypt_file(path=path)
        shutil.unpack_archive(restore_path)
        pass
    def encrypt(self, path):
        if os.path.isdir(path):
            self._encrypt_folder(path)
        else:
            self._encrypt_file(path)

        self.cur.close()
        print("[INFO] Encryption Completed Check Your Backup Folder: ", self.backup_path)
        pass
    def decrypt(self, path):

        if (path.find("zip"))>0:
            self._decrypt_folder(path)
        else:
            self._decrypt_file(path=path)
        print("[INFO] Decryption Completed Check Your Restore Folder: ", self.restore_path)
        self.cur.close()
        pass

    def share_key(self, path = "share_key/"):
        fp = open(path + self.email + "_receiver.pem", "wb")
        fp.write(self.public_key.export_key())
        fp.close()

        self.cur.close()
        pass

# Defining Menu
TITLE = "######################## MENU #######################"
menu = \
'''1. Create Encrypted Backup (File/Folder)
2. Decrypt My Backup 
3. Send Public Key'''
FOOTER = "############### SELECT FROM THE MENU ###############"

def main():
    # os.path.getmtime(path) :: get last modified date
    # 
    print("Each user is identifable by their email")
    email = "None"
    # regular expresion for validating email: chech for the format *****@*****.***
    regex = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"

    while not re.match(regex,email):
    
        # prompt for valid email or quit
        if email != "None":
            print("Invalid Email, Enter a valid email or Enter q to quite.")
        email = input("Enter User Email: ")

        if email.lower()=="q":
            break

    if re.match(regex,email):
        user_rsa = RSA_secure(email)
        choice = "-1"
        while int(choice) < 0 or int(choice) > len(menu.split("\n")) :
            print(TITLE)
            print(menu)
            print(FOOTER)
            if choice == "None":
                print("Invalid Choice")

            choice = int(input("Choose from the menu (e.g. 1) "))
        
        if choice == 1:
            encrypted_file = input("Enter the plain file/folder: ")
            user_rsa.encrypt(encrypted_file)
        elif choice == 2:
            encrypted_file = input("Enter the encrypted file/folder: ")
            user_rsa.decrypt(encrypted_file)
        elif choice == 3:
            ip = ""
            user_rsa.share_key()
            pass
    pass

if __name__ == "__main__":

    main()