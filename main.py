#!/usr/bin/env python

import math
import pickle
import string
import random
import getpass
import argparse
import requests
import tkinter as tk
from os.path import isdir
from os.path import isfile
from fuzzywuzzy import fuzz
from shutil import copyfile
from subprocess import call
from termcolor import colored
from tkinter.filedialog import askdirectory
from selenium.common.exceptions import WebDriverException
from exceptions import *
from account import *
from keycrypt import *


__author__ = "Akshay R. Kapadia"
__copyright__ = "Copyright 2018, Akshay R. Kapadia"
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Akshay R. Kapadia"
__email__ = "akshayrkapadia@tutamail.com"
__status__ = "Development"


class KeyCrypt:
    def __init__(self, path=None):
        try:
            if path is not None:
                # Restores data file from the given path
                KeyCrypt.restore(path)
            if isfile(".KeyCryptData.txt.gpg"):  # Checks to see if the file exists
                self.decrypt()
            with open(r".KeyCryptData.txt", "rb") as data_file:
                keycrypt_data = pickle.load(data_file)
                # Loads the keycrypt_data into the current instance of KeyCrypt
                self.accounts = keycrypt_data["Accounts"]
                self.gpg_name = keycrypt_data["GPG Name"]
                self.wifi_permission = keycrypt_data["Wifi Permission"]
                self.passwords_visible = keycrypt_data["Passwords Visible"]
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

    def encrypt(self):
        call(["gpg", "-e", "-r", str(self.gpg_name), ".KeyCryptData.txt"])
        call(["shred", "-u", ".KeyCryptData.txt"])

    # Decrypts the ".KeyCryptData.txt.gpg" file to ".KeyCryptData.txt"
    # Destroys the leftover file
    def decrypt(self):
        call(["gpg", "-d", "-o", ".KeyCryptData.txt", ".KeyCryptData.txt.gpg"])
        if isfile(".KeyCryptData.txt"):
            call(["shred", "-u", ".KeyCryptData.txt.gpg"])
        else:
            raise GPGError

    # Stores the KeyCrypt and name global variables in a dictionary.
    # Serializes the dictionary to ".KeyCryptData.txt" and encrypts the file
    def save(self):
        if not isfile(".KeyCryptData.txt.gpg"):
            data = {"Accounts": self.accounts, "GPG Name": self.gpg_name,
                    "Wifi Permission": self.wifi_permission, "Passwords Visible": self.passwords_visible}
            with open(r".KeyCryptData.txt", "wb") as data_file:
                pickle.dump(data, data_file)
            self.encrypt()

    # Backup .KeyCryptData.txt.gpg to the specified destination
    def backup(self, path):
        if isfile(".KeyCryptData.txt"):
            self.encrypt()
        if isdir(path):
            copyfile(".KeyCryptData.txt.gpg", path +
                     "/KeyCryptDataBackup.txt.gpg")
        else:
            raise FileNotFoundError

    # Updates all the security status for all the accounts
    def update(keycrypt):
        for account in keycrypt.accounts:
            account.update_security_status(keycrypt)

    # Restores data from the .KeyCryptData.txt.gpg file in the specified path
    def restore(path):
        if isdir(path):
            copyfile(path + "/KeyCryptDataBackup.txt.gpg",
                     ".KeyCryptData.txt.gpg")
        else:
            raise FileNotFoundError

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


class GUI():
    def start(self):
        pass


def banner():
    print(colored("______________________________________________________________________________________", "green"))
    print(colored("""
    888    d8P                     .d8888b.                            888
    888   d8P                     d88P  Y88b                           888
    888  d8P                      888    888                           888
    888d88K      .d88b.  888  888 888        888d888 888  888 88888b.  888888
    8888888b    d8P  Y8b 888  888 888        888P"   888  888 888 "88b 888
    888  Y88b   88888888 888  888 888    888 888     888  888 888  888 888
    888   Y88b  Y8b.     Y88b 888 Y88b  d88P 888     Y88b 888 888 d88P Y88b.
    888    Y88b  "Y8888   "Y88888  "Y8888P"  888      "Y88888 88888P"   "Y888
                              888                         888 888
                         Y8b d88P                    Y8b d88P 888
                          "Y88P"                      "Y88P"  888
                                                                                """, "blue"))
    print(colored("                      -</Encrypted Password Manager/>-", "red"))
    print(colored("______________________________________________________________________________________", "green"))


def main():
    parser = argparse.ArgumentParser(
        prog="KeyCrypt", description="Secure Password Manager With GPG Encryption", epilog="KeyCrypt Copyright (C) 2018 Akshay R. Kapadia")
    subparsers = parser.add_subparsers(dest="command")  # Primary command
    add_subparser = subparsers.add_parser("add")
    delete_subparser = subparsers.add_parser("delete")
    edit_subparser = subparsers.add_parser("edit")
    find_subparser = subparsers.add_parser("find")
    login_subparser = subparsers.add_parser("login")
    see_subparser = subparsers.add_parser("see")
    backup_subparser = subparsers.add_parser("backup")
    restore_subparser = subparsers.add_parser("restore")
    settings_subparser = subparsers.add_parser("settings")
    nuke_subparser = subparsers.add_parser("nuke")

    # Add account parser
    add_subparser.add_argument("name", help="Name of the account", type=str)
    add_subparser.add_argument("-r", "--random-password",
                               help="Generates a random ASCII password of the specified length", type=int)

    # Delete account parser
    delete_subparser.add_argument("name", help="Name of the account", type=str)

    # Edit account parser
    edit_subparser.add_argument("name", help="Name of the account", type=str)
    edit_subparser.add_argument("-pv", "--password-visible",
                                help="Makes the password visible with the account data is shown", action="store_true")

    # Find account parser
    find_subparser.add_argument("name", help="Name of the account", type=str)
    find_subparser.add_argument("-pv", "--password-visible",
                                help="Makes the password visible with the account data is shown", action="store_true")

    # Autologin parser
    login_subparser.add_argument("name", help="Name of the account", type=str)

    # See category parser
    see_subparser.add_argument(
        "category", help="The category that you want to see", type=str)
    see_subparser.add_argument("-pv", "--password-visible",
                               help="Makes the password visible with the account data is shown", action="store_true")

    # Backup Parser
    backup_subparser.add_argument(
        "-d", "--delete", help="Deletes the original copy of the KeyCrypt data", action="store_true")
    backup_subparser.add_argument(
        "path", help="The path to the destination directory (Enter '?' to open the directory chooser", type=str)

    # Restore parser
    restore_subparser.add_argument(
        "-d", "--delete", help="Deletes the backed up copy of the KeyCrypt data", action="store_true")
    restore_subparser.add_argument(
        "-m", "--merge", help="Merges the accounts in the backup file with your current KeyCrypt", action="store_true")
    restore_subparser.add_argument(
        "path", help="The path to the directory where the backup is located (Enter '?' to open the directory chooser)", type=str)

    args = vars(parser.parse_args())

    keycrypt = KeyCrypt()
    try:
        if args["command"] == "nuke":
            confirmation = True if (str(input(colored(
                "Are You Sure You Want To Permanently Nuke The KeyCrypt (y/N): ", "red"))).lower() in ["y", "yes"]) else False
            if confirmation:
                confirmation_key = KeyCrypt.generate_password(
                    30, regenerate=False)
                typed_confirmation_key = str(
                    input(colored("Type ", "red") + colored(str(confirmation_key), "yellow") + colored(" To Nuke The KeyCrypt: ", "red")))
                if typed_confirmation_key == confirmation_key:
                    call(["shred", "-u", ".KeyCryptData.txt"])
                    print(colored("KeyCrypt Successfully Nuked", "green"))
                else:
                    print(colored("KeyCrypt Nuke Cancelled", "red"))
            else:
                print(colored("KeyCrypt Nuke Cancelled", "red"))
        else:
            keycrypt.gpg_name = str(input("Name Associated With GPG Key: ")
                                    ) if keycrypt.gpg_name is None else keycrypt.gpg_name
            if args["command"] == "backup":
                path = args["path"]
                if path == "?":
                    tk.Tk().withdraw()
                    path = askdirectory()
                if path == "":
                    raise tk.TclError
                else:
                    keycrypt.backup(path)
                    if args["delete"]:
                        call(["shred", "-u", ".KeyCryptData.txt"])
                    else:
                        keycrypt.save()
                print(colored("KeyCrypt Successfully Backed Up", "green"))
            else:
                try:
                    if args["command"] is None:
                        banner()
                        KeyCrypt.update(keycrypt)
                        for account in keycrypt.accounts:
                            account.show_account(keycrypt.wifi_permission)
                    elif args["command"] == "restore":
                        path = args["path"]
                        if path == "?":
                            tk.Tk().withdraw()
                            path = askdirectory()
                        if path == "":
                            raise tk.TclError
                        else:
                            if args["merge"]:
                                old_accounts = keycrypt.accounts
                                keycrypt = KeyCrypt(path)
                                for account_x in old_accounts:
                                    duplicate = False
                                    for account_y in keycrypt.accounts:
                                        if account_x.equals(account_y):
                                            duplicate = True
                                    if not duplicate:
                                        keycrypt.add_account(account_x)
                            else:
                                keycrypt = KeyCrypt(path)
                            if args["delete"]:
                                call(["shred", "-u", path +
                                      "/KeyCryptDataBackup.txt.gpg"])
                            print(colored("KeyCrypt Successfully Restored", "green"))
                    elif args["command"] == "settings":
                        print(colored("Settings", "red"))
                        if keycrypt.wifi_permission:
                            print("Wifi Permission (Security Status & Autologin): " +
                                  colored(keycrypt.wifi_permission, "green"))
                        else:
                            print("Wifi Permission (Security Status & Autologin): " +
                                  colored(keycrypt.wifi_permission, "red"))
                        if keycrypt.passwords_visible:
                            print("Passwords Visible: " +
                                  colored(keycrypt.passwords_visible, "green"))
                        else:
                            print("Passwords Visible: " +
                                  colored(keycrypt.passwords_visible, "red"))
                        setting = str(input("Setting: ")).lower().capitalize()
                        for defined_setting in ["Wifi Permission", "Passwords Visible"]:
                            if fuzz.partial_ratio(setting, defined_setting) >= 50:
                                setting = defined_setting
                        if setting not in ["GPG Name", "Wifi Permission", "Passwords Visible"]:
                            raise InvalidSettingError
                        if setting == "Wifi Permission":
                            keycrypt.wifi_permission = not keycrypt.wifi_permission
                            if keycrypt.wifi_permission:
                                print("Wifi Permission (Security Status & Autologin): " +
                                      colored(keycrypt.wifi_permission, "green"))
                            else:
                                print("Wifi Permission (Security Status & Autologin): " +
                                      colored(keycrypt.wifi_permission, "red"))
                        else:
                            keycrypt.passwords_visible = not keycrypt.passwords_visible
                            if keycrypt.passwords_visible:
                                print("Passwords Visible: " +
                                      colored(keycrypt.passwords_visible, "green"))
                            else:
                                print("Passwords Visible: " +
                                      colored(keycrypt.passwords_visible, "red"))
                    elif args["command"] == "add":
                        username = str(input("Username: "))
                        password = KeyCrypt.generate_password(
                            args["random_password"]) if args["random_password"] is not None else getpass.getpass("Password: ")
                        category = str(
                            input("Category (Email, Web, Social, Banking, Computer, Other): ")).lower().capitalize()
                        for defined_category in ["Email", "Web", "Social", "Banking", "Computer", "Other"]:
                            if fuzz.ratio(category, defined_category) >= 70:
                                category = defined_category
                        if category not in ["Email", "Web", "Social", "Banking", "Computer", "Other"]:
                            raise InvalidCategoryError
                        url = str(
                            input("Url (Use Login Page For Autologin)(Start With 'https://'): "))
                        account = Account(args["name"], username, password, url,
                                          category, keycrypt)
                        keycrypt.add_account(account)
                        account.show_account(False)
                        print(
                            colored(args["name"] + " Account Successfully Created", "green"))
                        autologin = False if (
                            str(input("Configure Autologin (Y/n): ")) in ["n", "no"]) else True
                        if autologin:
                            if KeyCrypt.wifi_enabled(keycrypt.wifi_permission):
                                account.configure_autologin()
                            else:
                                account.autologin = False
                                raise NoInternetError
                        if (account.username_id is None or account.password_id is None):
                            account.autologin = False
                        else:
                            account.autologin = True
                    elif args["command"] == "see":
                        if keycrypt.passwords_visible:
                            args["password_visible"] = True
                        args["category"] = (
                            args["category"].lower()).capitalize()
                        for defined_category in ["Email", "Web", "Social", "Banking", "Computer", "Other", "All"]:
                            if fuzz.ratio(args["category"], defined_category) >= 70:
                                args["category"] = defined_category
                        if args["category"] not in ["Email", "Web", "Social", "Banking", "Computer", "Other", "All"]:
                            raise InvalidCategoryError
                        if args["category"] == "All":
                            KeyCrypt.update(keycrypt)
                            for account in keycrypt.accounts:
                                account.show_account(keycrypt.wifi_permission,
                                                     args["password_visible"])
                        else:
                            for account in keycrypt.accounts:
                                if account.category == args["category"]:
                                    account.update_security_status(keycrypt)
                                    account.show_account(keycrypt.wifi_permission,
                                                         args["password_visible"])
                    else:
                        account = keycrypt.find_account(args["name"])
                        if args["command"] == "delete":
                            account.show_account(False, False)
                            confirmation = True if (str(input(colored("Are You Sure You Want To Permanently Delete Your " +
                                                                      account.name + " Account (y/N): ", "red"))).lower() in ["y", "yes"]) else False
                            if confirmation:
                                confirmation_key = KeyCrypt.generate_password(
                                    15, False)
                                typed_confirmation_key = str(
                                    input(colored("Type ", "red") + colored(str(confirmation_key), "yellow") + colored(" To Delete Your " + account.name + " Account: ", "red")))
                                if typed_confirmation_key == confirmation_key:
                                    keycrypt.delete_account(account)
                                    print(colored(account.name +
                                                  " Account Deleted", "green"))
                                else:
                                    print(
                                        colored("Account Deletion Cancelled", "red"))
                            else:
                                print(colored("Account Deletion Cancelled", "red"))
                        elif args["command"] == "edit":
                            if keycrypt.passwords_visible:
                                args["password_visible"] = True
                            account.update_security_status(keycrypt)
                            account.show_account(
                                keycrypt.wifi_permission, args["password_visible"])
                            attribute = str(input("Attribute: ")
                                            ).lower().capitalize()
                            for defined_attribute in ["Name", "Username", "Password", "Url", "Category", "Autologin"]:
                                if fuzz.ratio(attribute, defined_attribute) >= 70:
                                    attribute = defined_attribute
                            if attribute not in ["Name", "Username", "Password", "Url", "Category", "Autologin"]:
                                raise InvalidAttributeError
                            account.edit_account(attribute, keycrypt)
                            account.update_security_status(keycrypt)
                            account.show_account(
                                keycrypt.wifi_permission, args["password_visible"])
                            print(
                                colored(attribute + " Successfully Edited", "green"))
                        elif args["command"] == "login":
                            if KeyCrypt.wifi_enabled(keycrypt.wifi_permission):
                                if (account.autologin and account.username_id is not None and account.password_id is not None):
                                    print(colored("Logging Into Your " +
                                                  account.name + " Account...", "red"))
                                    account.login()
                                    print(
                                        colored("Successfully Entered Login Information", "green"))
                                else:
                                    raise AccountNotConfiguredError(
                                        "Account Is Not Configured For Autologin", account)
                            else:
                                raise NoInternetError
                        elif args["command"] == "find":
                            if keycrypt.passwords_visible:
                                args["password_visible"] = True
                            for account in keycrypt.find_account(args["name"], True):
                                account.update_security_status(keycrypt)
                                account.show_account(keycrypt.wifi_permission,
                                                     args["password_visible"])
                except InvalidCategoryError:
                    print(colored("Invalid Category", "red"))
                    print(colored(
                        "Categories: Web, Social, Computer, Banking, Email, Other (, All)", "red"))
                except InvalidAttributeError:
                    print(colored("Invalid Account Attribute", "red"))
                    print(
                        colored("Attributes: Name, Username, Password, Url, Category", "red"))
                except InvalidSettingError:
                    print(colored("Invalid Setting", "red"))
                    print(
                        colored("Settings: GPG Name, Wifi Permission, Passwords Visible", "red"))
                except tk.TclError:
                    print(colored("Invalid Directory", "red"))
                except NoInternetError:
                    print(colored("No Internet Connection", "red"))
                except WebDriverException:
                    if "gecko" in str(WebDriverException):
                        print(colored("'geckodriver' Not Installed", "red"))
                    else:
                        print(colored("Incorrect Account Information", "red"))
                finally:
                    if isfile("geckodriver.log"):
                        call(["shred", "-u", "geckodriver.log"])
                    keycrypt.save()
    except FileNotFoundError:
        print(colored("File Not Found", "red"))
    except ValueError:
        print(colored("Invalid Input, Try Again", "red"))


if __name__ == "__main__":
    main()
