#!\usr\bin\python3 
# python = 3.6.13  


from secrets import token_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

import fabric
from getpass import getpass

import sqlite3
import os
import re
import shutil
# plain_text = "abcdefghijklmnopqrstuvwxyz"

# key = ""
# iv = ""
# aes_cipher = Cipher(algorithm=algorithms.AES(), mode=modes.GCM())
class RSA_secure:
    def __init__(self, email ):

        self.email = email
        self.encrypt_ext = ".encrypted"
        self.archive = "zip"
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

        self.backup_path = email+"_backup" + os.path.sep
        self.restore_path = email+"_restore" + os.path.sep
        os.makedirs(self.restore_path, exist_ok=True)
        os.makedirs(self.backup_path, exist_ok=True)

        conn.commit()
        pass

    def _encrypt_file(self, path):

        # read the 
        fp_plain = open(path, 'rb')
        plain_fp_content = fp_plain.read()
        fileName = path.split(os.path.sep)[-1] + self.encrypt_ext
        fp_cipher = open(self.backup_path + fileName, 'wb')

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
        temp = path.split(os.path.sep)[-1]

        plain_file = self.restore_path+".".join(temp.split(".")[:-1])

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
        shutil.make_archive(output_filename, self.archive, path)
        path = output_filename+"."+self.archive

        
        self._encrypt_file(path=path)
        # fp = open(path, "rb")
        # plain_content = fp.read()
        os.remove(path)
        pass

    def _decrypt_folder(self, path):
        restore_path = self._decrypt_file(path=path)
        temp = ".".join(restore_path.split(".")[:-1])
        print(temp)
        shutil.unpack_archive(restore_path, temp)
        os.remove(restore_path)
        pass
    def encrypt(self, path):
        

        time_of_last_modified = os.path.getmtime(path)
        
        if os.path.isdir(path):
            last_backup = os.path.join(self.backup_path, path + "." + self.archive + self.encrypt_ext)
            print("[INFO] Checking for your backup histories ", last_backup)
            if os.path.exists(last_backup): # works for folder
                print("[INFO] Found a backup.")
                time_of_last_backup = os.path.getmtime(last_backup)
                diff = time_of_last_backup - time_of_last_modified
                if diff > 0:
                    print("[INFO] The source has not been recently modified.")
                    exit()

            self._encrypt_folder(path)
        else:
            fileName = path.split(os.path.sep)[-1]
            last_backup = os.path.join(self.backup_path, fileName + self.encrypt_ext)
            if os.path.exists(last_backup): # works for file
                print("[INFO] Found a backup.")
                time_of_last_backup = os.path.getmtime(last_backup)
                diff = time_of_last_backup - time_of_last_modified
                print("Time of last backup {}\nTime of last modification {}".format(time_of_last_backup,time_of_last_modified))
                if diff > 0:
                    print("[INFO] The source has not been recently modified.")
                    exit()

            self._encrypt_file(path)
        print("[INFO] Previous backup has been overwritten.")
        self.cur.close()
        print("[INFO] Encryption Completed Check Your Backup Folder: ", self.backup_path)
        pass
    def decrypt(self, path):

        if (path.find(self.archive))>0:
            self._decrypt_folder(path)
        else:
            self._decrypt_file(path=path)
        print("[INFO] Decryption Completed Check Your Restore Folder: ", self.restore_path)
        self.cur.close()
        pass

    def share_key(self, path = "share_key"+os.path.sep, ssh_config = None):

        local_path = path + self.email + "_receiver.pem"
        fp = open(local_path, "wb")
        fp.write(self.public_key.export_key())
        fp.close()

        if ssh_config is not None:
            print("[INFO] Sending Key to Remote Server")
            remote_path = ".ssh/{}".format(self.email + "_receiver.pem")

            c = fabric.Connection(ssh_config["IP"], port=ssh_config["PORT"], user=ssh_config["USER"], connect_kwargs={'password': ssh_config["PWD"]})
            
            c.put(local_path, remote=remote_path)

            pass
        print("[INFO] Key Successully Shared")
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
            if(not os.path.exists(encrypted_file)):
                print("[ERR] File or Folder Does Not Exist !")
                exit()
            user_rsa.encrypt(encrypted_file)

        elif choice == 2:

            encrypted_file = input("Enter the encrypted file: ")
            if(not os.path.exists(encrypted_file)):
                print("[ERR] File or Folder Does Not Exist !")
                exit()
            user_rsa.decrypt(encrypted_file)

        elif choice == 3:

            prompt = input("Do you want to send key to remote server? (Y/N) ")
            ssh_config = None

            if prompt.lower() == "y":
                IP = input("Enter the remote IP: (e.g. 127.0.0.1) ")
                USER = input("Enter the remote username: (e.g. root) ")
                # PORT = input("Enter the remote IP: (e.g. 127.0.0.1) ")
                
                PWD = getpass("Enter the server's password: ")
                ssh_config = {
                    "IP": IP,
                    "USER": USER,
                    "PORT":22,
                    "PWD": PWD
                }
            user_rsa.share_key(ssh_config=ssh_config)

            pass
    pass

if __name__ == "__main__":
# 
    main()