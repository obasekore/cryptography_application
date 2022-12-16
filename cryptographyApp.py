#!\usr\bin\python3 
# python = 3.6.13  

# ****Importing cryptography library*****
from secrets import token_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# Importing remote communication library
import fabric

# Importing library to hide password in input terminal 
from getpass import getpass

# Library for databse manipulation
import sqlite3

# python built-in library
import os # Manipulate Operating System 
import re # Manipulate Regular Expression
import shutil

# ************************* Section 1 Begin *******************************************
class RSA_secure:
    def __init__(self, email, encrypt_ext = ".encrypted", archive = "zip"): # constructor

        # assign email of the user
        self.email = email 
        # final extension of the encrypted file
        self.encrypt_ext = encrypt_ext 
        # choosen compression extension
        self.archive = archive
        # database columns
        self.columns = {"email":0, "public_key":1, "private_key":2}
        # create database for users
        conn = sqlite3.connect('userdb.sqlite')
        self.cur = conn.cursor()
        # create users' table in the database (if not already existing)
        # self.cur.execute('''CREATE TABLE IF NOT EXISTS Users (email TEXT, public_key TEXT, private_key TEXT)''')
        _list_column = list(self.columns.keys())
        self.cur.execute('''CREATE TABLE IF NOT EXISTS Users ({} TEXT, {} TEXT, {} TEXT)'''.format(_list_column[0], _list_column[1], _list_column[2]))
        
        # select the user from the database using email
        self.cur.execute('SELECT * FROM Users WHERE email = ? ', (email,))
        row = self.cur.fetchone() # just one user
        if row is None: # if there is no user already registered in the db with the email
            # generate key
            key = RSA.generate(2048)

            # assign private key
            self.private_key = key

            # assign public key 
            self.public_key = key.publickey()
            # register the new user into the database with email, private-key and public-key
            self.cur.execute('''INSERT INTO Users ({}, {}, {})
                VALUES (?, ?, ?)'''.format(_list_column[0], _list_column[1], _list_column[2]), (email, self.public_key.export_key(), self.private_key.export_key()))

            print("[INFO] New Public & Private Keys Generated for User {}...".format(email))
        else:
            # if the user with the email is found

            # Load the user's existing keys
            self.public_key = RSA.import_key(row[self.columns["public_key"]])
            self.private_key = RSA.import_key(row[self.columns["private_key"]])
            print("[INFO] Loading Public & Private Keys for User {}...".format(row[self.columns["email"]]))

        # Generate name for backup and restore for signed in user
        self.backup_path = email+"_backup" + os.path.sep
        self.restore_path = email+"_restore" + os.path.sep
        os.makedirs(self.restore_path, exist_ok=True) # create restore folder for signed in user
        os.makedirs(self.backup_path, exist_ok=True) # create backup folder for signed in user
        # 
        conn.commit()
        pass

    def __encrypt_file(self, path):
        """
        This is a private method for encrypting files only
        """
        # Open the plain file for reading
        fp_plain = open(path, 'rb')
        # read the content of the plain file
        plain_fp_content = fp_plain.read()
        # extract the filename from the path and add the encryption extension
        fileName = path.split(os.path.sep)[-1] + self.encrypt_ext
        # Create an empty file to write the encrypted copy
        fp_cipher = open(self.backup_path + fileName, 'wb')

        # create a random byte string containing 32 bytes.
        aes_key = token_bytes(32)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.public_key) # create a cipher object PKCS1OAEP_Cipher that can be used to perform PKCS#1 OAEP encryption.
        enc_session_key = cipher_rsa.encrypt(aes_key) # session key with the public RSA key
        
        aes_cipher = AES.new(aes_key, AES.MODE_GCM)
        (cipher, tag) = aes_cipher.encrypt_and_digest(plain_fp_content) # create encrypted copy of the plain file
        [ fp_cipher.write(x) for x in (enc_session_key, aes_cipher.nonce, tag, cipher) ] # write the encrypted copy into the created empty file

        fp_cipher.close()   # close the encrypted file
        fp_plain.close()    # close the plain file
        pass

    def __decrypt_file(self, path):
        
        """
        This is a private method to decrypt files
        """
        encrypted_file = path
        cipher_file = open(encrypted_file, 'rb') # open the encrypted file 
        temp = path.split(os.path.sep)[-1] # extract the name of the encrypted file

        plain_file = self.restore_path+".".join(temp.split(".")[:-1]) # generate the name of the empty restore copy

        fp_plain_restore = open(plain_file, 'wb') # create an empty restore file
        private_key = self.private_key # get the private key

        enc_session_key, nonce, tag, ciphertext = [ cipher_file.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ] # read the content of the encrypted file 
        cipher_rsa = PKCS1_OAEP.new(private_key)   # create a cipher object PKCS1OAEP_Cipher that can be used to perform PKCS#1 OAEP decryption.
        try: # peventing ability to decrypt other user's file with wrong key
            session_key = cipher_rsa.decrypt(enc_session_key) # session key with the private RSA key
            aes_cipher = AES.new(session_key, AES.MODE_GCM,nonce=nonce)
            decrypted = aes_cipher.decrypt_and_verify(ciphertext,tag)   # create decrypted copy of the encrypted file
            fp_plain_restore.write(decrypted) # write the decrypted copy into the created empty file
            

        except ValueError as e:
            fp_plain_restore.close()    # close the empty file
            os.remove(plain_file)       # remove the empty file
            print("[ERR] Attempting to decrypt other user's backup with own's key...")
            exit()

        fp_plain_restore.close()    # close the decrypted file
        cipher_file.close()         # close the encrypted file
        return plain_file           # return the path to the decrypted file
        pass

    def __encrypt_folder(self, path):
        
        """
            This is a private method for encrypting folders
        """

        # zip
        # convert the folder to file by making a compressed archive
        output_filename = path # use the folder path as file name
        shutil.make_archive(output_filename, self.archive, path) # create the archive based on the choosing compression e.g .zip
        path = output_filename+"."+self.archive # generate the filename for the archive by inferring

        # call the private __encrypt_file method to  
        self.__encrypt_file(path=path) 
        # delete the compressed file
        os.remove(path)
        pass

    def __decrypt_folder(self, path):
        """
        This private method decrypt folder
        """
        # call the private decrypt file method and get path to the decrypted file
        restore_path = self.__decrypt_file(path=path)
        # extract the name of the file
        temp = ".".join(restore_path.split(".")[:-1]) # 
        # restore the folder by decompressing the file
        shutil.unpack_archive(restore_path, temp)
        # delete the temporary compressed file
        os.remove(restore_path) 
        pass
    def encrypt(self, path):
        
        """
        This public method encrypt serves as entry point method for the
        private encrypt_file or encrypt_folder depending on the user's input
        if the user provide folder, it uses the __encrypt_folder
        else it use the __encrypt_file
        """
        # get the epoch timestamp the file was last modified 
        time_of_last_modified = os.path.getmtime(path)
        
        if os.path.isdir(path): # if it's a folder
            # generate path & name for the probable last backup
            last_backup = os.path.join(self.backup_path, path + "." + self.archive + self.encrypt_ext)
            print("[INFO] Checking for your backup histories ", last_backup)
            if os.path.exists(last_backup): # If the probable last backup is a folder
                print("[INFO] Found a backup.")
                # get the epoch timestamp of the previous backup
                time_of_last_backup = os.path.getmtime(last_backup)
                # calculate the time difference
                diff = time_of_last_backup - time_of_last_modified
                if diff > 0: # if the backup is more recent 
                    print("[INFO] The source has not been recently modified.")
                    exit() # cancel the backup process
            # call the private folder encrypt method
            self.__encrypt_folder(path)
        else: # otherwise it's a file
            # generate the path and name for the probable last backup file
            fileName = path.split(os.path.sep)[-1]
            last_backup = os.path.join(self.backup_path, fileName + self.encrypt_ext)
            if os.path.exists(last_backup): # works for file
                print("[INFO] Found a backup.")
                # get the epoch timestamp of the previous backup file
                time_of_last_backup = os.path.getmtime(last_backup)
                # compute the time difference
                diff = time_of_last_backup - time_of_last_modified
                print("Time of last backup {}\nTime of last modification {}".format(time_of_last_backup,time_of_last_modified))
                if diff > 0: # if the last backup file is more recent
                    print("[INFO] The source has not been recently modified.")
                    exit() # terminate the file backup process
            # call the private method for file encryption
            self.__encrypt_file(path)
        print("[INFO] Previous backup has been overwritten.")
        self.cur.close() # close previously opened database connection
        print("[INFO] Encryption Completed Check Your Backup Folder: ", self.backup_path)
        pass
    def decrypt(self, path):
        """
        This public method serves as the entry point for the decrypting either file or folder
        The previously encrypted folder contains the choosen archive extension in the filename
        """
        if (path.find(self.archive))>0: # if the choosen archive extension is in the path
            # call the private decrypt folder method
            self.__decrypt_folder(path)
        else: # other wise it's a file
            # call the private decrypt file method
            self.__decrypt_file(path=path)
        print("[INFO] Decryption Completed Check Your Restore Folder: ", self.restore_path)
        self.cur.close() # close previously opened database connection
        pass

    def share_key(self, path = "share_key"+os.path.sep, ssh_config = None):
        """
        This method is for key management. 
        It shares the user's public key as a file (and over ssh to remote server)
        """
        # create folder for sharing key
        os.makedirs(path, exist_ok=True)
        # create the file name for the key
        local_path = path + self.email + "_receiver.pem"
        # open empty file for the key
        fp = open(local_path, "wb")
        # write the public key into the empty file
        fp.write(self.public_key.export_key())
        # close the file
        fp.close()

        if ssh_config is not None: # if the ssh configuration is provided
            print("[INFO] Sending Key to Remote Server")
            # create the path to write the public key on the remote server... e.g. .ssh/default@defualt.com_receiver.pem
            remote_path = ".ssh/{}".format(self.email + "_receiver.pem")
            # establish an ssh connection 
            c = fabric.Connection(ssh_config["IP"], port=ssh_config["PORT"], user=ssh_config["USER"], connect_kwargs={'password': ssh_config["PWD"]})
            # copy the key over the ssh network
            c.put(local_path, remote=remote_path)

            pass
        print("[INFO] Key Successully Shared")
        self.cur.close() # close database
        pass

# ************************* Section 2 Begin *******************************************
# Variables that define the Menu
TITLE = "######################## MENU #######################"
menu = \
'''1. Create Encrypted Backup (File/Folder)
2. Decrypt My Backup 
3. Send Public Key'''
FOOTER = "############### SELECT FROM THE MENU ###############"

# 
def main():
    """
    Main function for prompting & validating user and routing logic
    """
    print("\n\n\n#############################################################")
    print("Each user is identifable by their email")
    print("#############################################################\n\n")
    # Default email is set to none
    email = "None"
    # regular expresion for validating email: chech for the format *****@*****.***
    regex = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"

    while not re.match(regex,email): # continue until a valid email is provided
    
        # prompt for valid email or quit
        if email != "None": # check if user has previously entered an invalid email format 
            print("[ERR] Invalid Email, Enter a valid email or Enter q to quite.")
        # prompt user to enter email
        email = input("Enter User Email: ")

        if email.lower()=="q": # chjeck if user enter q to quite
            print("[INFO] Application cancelled by user ...")
            break # 

    if re.match(regex,email): # check if it's a valid email format
        user_rsa = RSA_secure(email) # Instantiate the encryption-decryption object
        choice = "-1" # intialize default value
        while int(choice) < 0 or int(choice) > len(menu.split("\n")) : #continue until a valid choice is made
            print(TITLE)    # display title
            print(menu)     # display menu
            print(FOOTER)   # display footer
            if choice == "None": # check if no input has been provided
                print("[ERR] Invalid Choice")

            choice = int(input("Choose from the menu (e.g. 1) ")) # request for user's input choice and cast the type as integer
        
        if choice == 1: # check if 1 was enter
            # Request the path to the folder or file to encrypt 
            encrypted_file = input("Enter the plain file/folder: ") 
            if(not os.path.exists(encrypted_file)): # check if folder or file is not existing
                print("[ERR] File or Folder Does Not Exist !")
                exit() # quite the program\
            
            # otherwise call the public encrypt method
            user_rsa.encrypt(encrypted_file) 

        elif choice == 2: # check if option 2 was enter
             # Request the path to the folder or file to decrypt 
            encrypted_file = input("Enter the encrypted file: ")
            if(not os.path.exists(encrypted_file)): # check if encrypted file is not existing
                print("[ERR] File or Folder Does Not Exist !")
                exit() # quite the program
            
            # otherwise call the public decrypt method
            user_rsa.decrypt(encrypted_file)

        elif choice == 3: # check if option 3 was entered
            #  prompt user for additional choice of sending to remote server
            prompt = input("Do you want to send key to remote server? (Y/N) ")
            ssh_config = None
            # if yes
            if prompt.lower() == "y":
                # request the server's IP
                IP = input("Enter the remote IP: (e.g. 127.0.0.1) ") 
                # request the server's username
                USER = input("Enter the remote username: (e.g. root) ")
                # PORT = input("Enter the remote IP: (e.g. 127.0.0.1) ")
                # request the server's password as secured input
                PWD = getpass("Enter the server's password: ")
                # define the dictionary of ssh configuration
                ssh_config = {
                    "IP": IP,
                    "USER": USER,
                    "PORT":22,
                    "PWD": PWD
                }
            # call the share key method 
            user_rsa.share_key(ssh_config=ssh_config)

            pass
    pass

if __name__ == "__main__": # condition for determining if the application was imported or invoked
    # call the main function
    main()