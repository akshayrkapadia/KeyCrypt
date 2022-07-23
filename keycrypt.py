import math
import pickle
import string
import random
import requests
from os.path import isdir
from os.path import isfile
from fuzzywuzzy import fuzz
from shutil import copyfile
from subprocess import call
from termcolor import colored
from exceptions import *


class KeyCrypt:
    def __init__(self, path="", restore=False):
        try:
            filename = "KeyCryptDataBackup.txt" if restore else ".KeyCryptData.txt"
            if path != None:
                filename = path + filename
            print(filename)
            if isfile(filename+".gpg"):  # Checks to see if the file exists
                print("decrpyting")
                self.decrypt(filename)
                print("done dec")
                with open(filename, "rb") as data_file:
                    keycrypt_data = pickle.load(data_file)
                    # Loads the keycrypt_data into the current instance of KeyCrypt
                    self.accounts = keycrypt_data["Accounts"]
                    self.gpg_name = keycrypt_data["GPG Name"]
                    self.wifi_permission = keycrypt_data["Wifi Permission"]
                    self.passwords_visible = keycrypt_data["Passwords Visible"]
            else:
                self.gpg_name = None
                self.accounts = []
                self.wifi_permission = True
                self.passwords_visible = False
        except IOError:
            self.gpg_name = None
            self.accounts = []
            self.wifi_permission = True
            self.passwords_visible = False
        except GPGError:
            print(colored("Incorrect GPG Password", "red"))

    # Adds a new account to the KeyCrypt
    def add_account(self, account):
        self.accounts.append(account)

    # Removes the account from the KeyCrypt
    def delete_account(self, account):
        self.accounts.remove(account)

    # Finds the specified account
    def find_account(self, account_name, all=False):
        matching_accounts = list(
            filter(lambda account: fuzz.ratio(account.name.upper(), account_name.upper()) > 70, self.accounts))
        if len(matching_accounts) == 0:
            raise AccountDoesNotExistError
        if all:
            return matching_accounts
        else:
            if len(matching_accounts) == 1:
                return matching_accounts[0]
            else:
                for account, i in zip(matching_accounts, range(len(matching_accounts))):
                    print(str(i) + ") " + colored(account.name, "red") + "\n  Username: " +
                          colored(account.username, "blue") + "\n  Url: " + colored(account.url, "blue"))
                while True:
                    account_index = int(input("Select An Account Number: "))
                    if account_index not in range(len(matching_accounts)):
                        raise ValueError
                    else:
                        return matching_accounts[account_index]

    # Encrypts the ".KeyCryptData.txt" file to ".KeyCryptData.txt.gpg"
    # Destroys the leftover file

    def encrypt(self, filename):
        call(["gpg", "-e", "-r", str(self.gpg_name), filename])
        call(["shred", "-u", filename])

    # Decrypts the ".KeyCryptData.txt.gpg" file to ".KeyCryptData.txt"
    # Destroys the leftover file
    def decrypt(self, filename):
        call(["gpg", "-d", "-o", filename, filename + ".gpg"])
        if isfile(filename):
            call(["shred", "-u", filename + ".gpg"])
        else:
            raise GPGError

    # Stores the KeyCrypt and name global variables in a dictionary.
    # Serializes the dictionary to ".KeyCryptData.txt" and encrypts the file
    def save(self, filename=".KeyCryptData.txt"):
        if not isfile(filename + ".gpg"):
            data = {"Accounts": self.accounts, "GPG Name": self.gpg_name,
                    "Wifi Permission": self.wifi_permission, "Passwords Visible": self.passwords_visible}
            with open(filename, "wb") as data_file:
                pickle.dump(data, data_file)
            self.encrypt(filename)

    # Backup .KeyCryptData.txt.gpg to the specified destination
    def backup(self, path):
        if isfile(".KeyCryptData.txt"):
            self.encrypt(".KeyCryptData.txt")
        else:
            raise FileNotFoundError
        if isdir(path):
            copyfile(".KeyCryptData.txt.gpg", path +
                     "KeyCryptDataBackup.txt.gpg")
        else:
            raise PathNotFoundError

    # Restores data from the .KeyCryptData.txt.gpg file in the specified path
    def restore(path):
        if isdir(path):
            copyfile(path + "KeyCryptDataBackup.txt.gpg",
                     ".KeyCryptData.txt.gpg")
        else:
            raise PathNotFoundError

    # Restores and merges data from the KeyCryptDataBackup.txt.gpg file in the specified path
    def merge(self, path, delete=False):
        print("entered restore")
        target = KeyCrypt(path, True)
        print("target made")
        print(len(target.accounts))
        for target_account in target.accounts:
            print(target_account.name)
            duplicate = False
            for account in self.accounts:
                if target_account.equals(account):
                    duplicate = True
            if not duplicate:
                self.add_account(target_account)
        if delete:
            call(["shred", "-u", path + "KeyCryptDataBackup.txt"])
        else:
            target.encrypt(path + "KeyCryptDataBackup.txt")

    # Updates all the security status for all the accounts
    def update(keycrypt):
        for account in keycrypt.accounts:
            account.update_security_status(keycrypt)

    # Tests password strength based on length and alphabet
    def check_password_strength(password):
        lowercase = False
        uppercase = False
        numbers = False
        special_characters = False
        for character in password:
            if character in string.ascii_lowercase:
                lowercase = True
            if character in string.ascii_uppercase:
                uppercase = True
            if character in string.digits:
                numbers = True
            if character in string.punctuation:
                special_characters = True
        character_set_length = 0
        if lowercase:
            character_set_length += len(string.ascii_lowercase)
        if uppercase:
            character_set_length += len(string.ascii_uppercase)
        if numbers:
            character_set_length += len(string.digits)
        if special_characters:
            character_set_length += len(string.punctuation)
        entropy = math.log(character_set_length**len(password), 2)
        if entropy >= 120:
            return "Very Strong"
        elif entropy >= 90:
            return "Strong"
        elif entropy >= 60:
            return "Medium"
        elif entropy >= 30:
            return "Weak"
        else:
            return "Very Weak"

    # Generates a random password using the ASCII character set with the specified length
    def generate_password(length, regenerate=True):
        while True:
            password = "".join(random.SystemRandom().choice(
                string.printable.strip(string.whitespace)) for _ in range(length))
            print(password)
            if (KeyCrypt.check_password_strength(password) == "Strong" or KeyCrypt.check_password_strength(password) == "Very Strong"):
                if regenerate:
                    print("Password: " + colored(password, "blue"))
                    password_option = str(
                        input("(r)egenerate or (c)ontinue: ")).lower()
                    if password_option == "r":
                        continue
                    elif password_option == "c":
                        return password
                else:
                    return password

    # Checks is there is a working wifi connection
    def wifi_enabled(wifi_permission):
        if wifi_permission:
            try:
                requests.get("https://www.duckduckgo.com")
                return True
            except requests.ConnectionError:
                return False
        else:
            return False
