from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import csv
import base64
import os.path


def write_salt():
    """
    This function generates a random value and save it into a
    file to be used as a salt value.
    """
    salt = os.urandom(32)
    with open("salt.txt", "wb") as key_file:
        key_file.write(salt)
        key_file.close()


def load_salt():
    """
    This function loads the key from the current directory
    named `salt.txt` to use as a salt.
    """
    return open("salt.txt", "rb").read()


def load_key(input_master_pass):
    """
    This function uses the master password and salt to
    create an encryption key for the user.
    """
    encoded_input_pass = input_master_pass.encode()
    salt = load_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(encoded_input_pass))
    return Fernet(key)


def load_hash():
    """
    This function returns the user's password hash.
    """
    return open("hash.txt", "r").read()


def auth():
    """
    This function authenticates the user by comparing
    their hashed input with the hash value in 'hash.txt'
    """
    input_pass = input("Please Input Your Master Password To Do This: ")
    hashed_input_pass = hash_pass(input_pass)
    hashed_input = load_hash()
    if hashed_input_pass == hashed_input:
        return input_pass
    else:
        return False


def hash_pass(input_master_pass):
    """
    This function hashes a password passed as a parameter.
    """
    hashed_pass = hashlib.sha3_256(input_master_pass.encode()).hexdigest()
    return hashed_pass


def encrypt_data(input_master_pass, input_service, input_email, input_pass):
    """
    This function loads the key using the input master password
    and encrypts the data input by the user. This is then appended
    to the file 'data.csv'
    """
    f = load_key(input_master_pass)
    encrypted_service = str(f.encrypt(input_service), 'utf-8')
    encrypted_email = str(f.encrypt(input_email), 'utf-8')
    encrypted_pass = str(f.encrypt(input_pass), 'utf-8')
    with open('data.csv', mode='a', newline='') as data_file:
        csv_writer = csv.writer(data_file)
        csv_writer.writerow([encrypted_service, encrypted_email, encrypted_pass])
        print("Details Saved\n")
        data_file.close()


def decrypt_data(input_master_pass):
    """
    This function loads the decryption key and opens the data file
    in read mode. It then loops through the file, creating a heading
    row first, then decrypts each row and prints to the user.
    """
    f = load_key(input_master_pass)
    with open('data.csv', "r", encoding='utf-8', newline='') as data_file:
        csv_reader = csv.reader(data_file, delimiter=',')
        for row in csv_reader:
            try:
                decrypted_service = str(f.decrypt(row[0].encode()), 'utf-8')
                decrypted_email = str(f.decrypt(row[1].encode()), 'utf-8')
                decrypted_pass = str(f.decrypt(row[2].encode()), 'utf-8')
                print("\nService: " + str(decrypted_service))
                print("Email: " + str(decrypted_email))
                print("Password: " + str(decrypted_pass) + "\n")
            except InvalidToken:
                print("Decryption Unsuccessful")
        data_file.close()


def search(input_master_pass):
    """
    This function allows a user to search for a password.
    The master password input by the user is used to load
    the key used to decrypt the passwords. Each row is
    decrypted and printed to the user.
    """
    search_service = input("Please Enter Which Service You Are Looking For: ")
    f = load_key(input_master_pass)
    with open('data.csv', "r", encoding='utf-8') as data_file:
        csv_reader = csv.reader(data_file, delimiter=',')
        for row in csv_reader:
            try:
                decrypted_service = str(f.decrypt(row[0].encode()), 'utf-8')
                if decrypted_service == search_service:
                    decrypted_email = str(f.decrypt(row[1].encode()), 'utf-8')
                    decrypted_pass = str(f.decrypt(row[2].encode()), 'utf-8')
                    print("\nService: " + str(decrypted_service))
                    print("Email: " + str(decrypted_email))
                    print("Password: " + str(decrypted_pass) + "\n")
            except InvalidToken:
                print("Decryption Unsuccessful")


def rem_all_pass():
    """
    This function removes the passwords by clearing the
    'data.csv' file.
    """
    with open('data.csv', "w") as data_file:
        file.truncate()
        print("Passwords Removed\n")
        data_file.close()


def rem_pass(input_master_pass):
    """
    This function takes the master password and uses
    it to decrypt the service names. Any service names
    matching the user's input are removed. This is done
    through temporarily storing the non deleted data in
    a list. The file is then cleared and repopulated using
    the list.
    """
    search_service = input("Please Enter Which Service You Want To Delete: ")
    check = input("Are You Sure? Enter \"y\" to continue: ")
    if check == "y":
        print("Deleting\n")
    else:
        print("Returning To Menu\n")
        return
    f = load_key(input_master_pass)
    lines = list()
    with open('data.csv', "r", encoding='utf-8') as data_file:
        csv_reader = csv.reader(data_file, delimiter=',')
        for row in csv_reader:
            try:
                decrypted_service = str(f.decrypt(row[0].encode()), 'utf-8')
                if decrypted_service != search_service:
                    lines.append(row)
            except InvalidToken:
                print("Decryption Unsuccessful")
                lines.clear()
                return
        data_file.close()
    with open('data.csv', 'w') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerows(lines)


def change_pass(input_master_pass):
    """
    This replaces the hash in the hash file so the user
    can authenticate with their new password as well as
    decrypting and re encrypting their data with their
    new password so they can still access it.
    """
    old_pass = input_master_pass
    new_pass = input("Please enter your new password: ")
    hashed_new_pass = hash_pass(new_pass)
    confirm_pass = hash_pass(input("Please confirm your new password: "))
    if confirm_pass == hashed_new_pass:
        lines = list()
        with open('data.csv', "r", encoding='utf-8', newline='') as data_file:
            csv_reader = csv.reader(data_file, delimiter=',')
            for row in csv_reader:
                try:
                    f = load_key(old_pass)
                    decrypted_service = str(f.decrypt(row[0].encode()), 'utf-8')
                    decrypted_email = str(f.decrypt(row[1].encode()), 'utf-8')
                    decrypted_pass = str(f.decrypt(row[2].encode()), 'utf-8')
                    f = load_key(new_pass)
                    encrypted_service = str(f.encrypt(decrypted_service.encode()), 'utf-8')
                    encrypted_email = str(f.encrypt(decrypted_email.encode()), 'utf-8')
                    encrypted_pass = str(f.encrypt(decrypted_pass.encode()), 'utf-8')
                    lines.append([encrypted_service, encrypted_email, encrypted_pass])
                except InvalidToken:
                    print("Decryption Unsuccessful")
                    lines.clear()
                    return
            data_file.close()
        hash_file = open("hash.txt", "w")
        hash_file.write(hashed_new_pass)
        hash_file.close()
        print("Password Successfully Changed\n")
        with open('data.csv', 'w', newline='') as data_file:
            csv_writer = csv.writer(data_file)
            csv_writer.writerows(lines)
            data_file.close()
    else:
        print("Passwords Do Not Match\n")


"""
Initial checks to ensure all files are created.
"""
if not os.path.isfile('hash.txt'):
    master_pass = hash_pass(input("Please Choose a Master Password: "))
    file = open("hash.txt", 'w')
    file.write(master_pass)
    file.close()
if not os.path.isfile('salt.txt'):
    write_salt()
if not os.path.isfile('data.csv'):
    file = open("data.csv", 'x')
    file.close()


while 1 == 1:
    """
    Menu is looped allowing users to return
    when the selected function is completed.
    """
    print("""
    1. Add a Password
    2. Retrieve All Passwords
    3. Search For a Password
    4. Remove All Passwords
    5. Remove A Password
    6. Change Master Password
    q. Quit\n""")
    user_choice = input("Choose an option: ")
    if user_choice == "1":
        master_pass = auth()
        if master_pass:
            service = input("Please Input The Service: ").encode()
            email = input("Please Enter The Email Used For This Service: ").encode()
            password = input("Please Enter The Password For This Service: ").encode()
            encrypt_data(master_pass, service, email, password)
            input("Press Enter to continue...")
        else:
            print("Incorrect Master Password\n")
    elif user_choice == "2":
        master_pass = auth()
        if master_pass:
            decrypt_data(master_pass)
            input("Press Enter to continue...")
        else:
            print("Incorrect Master Password\n")
    elif user_choice == "3":
        master_pass = auth()
        if master_pass:
            search(master_pass)
            input("Press Enter to continue...")
        else:
            print("Incorrect Master Password\n")
    elif user_choice == "4":
        master_pass = auth()
        if master_pass:
            rem_all_pass()
            input("Press Enter to continue...")
        else:
            print("Incorrect Master Password\n")
    elif user_choice == "5":
        master_pass = auth()
        if master_pass:
            rem_pass(master_pass)
            input("Press Enter to continue...")
        else:
            print("Incorrect Master Password\n")
    elif user_choice == "6":
        master_pass = auth()
        if master_pass:
            change_pass(master_pass)
            input("Press Enter to continue...")
        else:
            print("Incorrect Master Password\n")
    elif user_choice == "q":
        print("Quitting\n")
        break
    else:
        print("\nPlease Enter a Valid Option")
