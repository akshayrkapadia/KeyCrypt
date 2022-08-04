#!/usr/bin/env python

import getpass
import argparse
from os.path import isfile
from fuzzywuzzy import fuzz
from subprocess import call
from termcolor import colored
from shutil import copyfile
from exceptions import *
from account import *
from keycrypt import *


__author__ = "Akshay R. Kapadia"
__copyright__ = "Copyright 2022, Akshay R. Kapadia"
__license__ = "GPL"
__version__ = "0.2.0"
__maintainer__ = "Akshay R. Kapadia"
__status__ = "Development"


# class GUI():
#     def start(self):
#         pass


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
                if ((len(path) > 0) and (path[-1] != "/")):
                    path += "/"
                if not isdir(path):
                    print(path)
                    raise PathNotFoundError
                else:
                    keycrypt.backup(path)
                    if args["delete"]:
                        call(["shred", "-u", ".KeyCryptData.txt.gpg"])
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
                        if ((len(path) > 0) and (path[-1] != "/")):
                            path += "/"
                        if not isfile(path + "KeyCryptDataBackup.txt.gpg"):
                            raise FileNotFoundError
                        else:
                            if isfile(".KeyCryptData.txt"):
                                delete = False
                                if args["delete"]:
                                    delete = True
                                if args["merge"]:
                                    keycrypt.merge(path, delete)
                                else:
                                    merge = True if (
                                        str(input("Data Already Exists. Merge? (y/N): ")).lower() in ["y", "yes"]) else False
                                    if merge:
                                        keycrypt.merge(path, delete)
                                    else:
                                        copyfile(path + "KeyCryptDataBackup.txt.gpg", ".KeyCryptData.txt.gpg")
                                        keycrypt = KeyCrypt()
                            else:
                                copyfile(path + "KeyCryptDataBackup.txt.gpg", ".KeyCryptData.txt.gpg")
                                keycrypt = KeyCrypt()
                            print(colored("KeyCrypt Successfully Restored", "green"))
                    elif args["command"] == "settings":
                        print(colored("Settings", "red"))
                        if keycrypt.wifi_permission:
                            print("Wifi Permission for Security Status: " +
                                  colored(keycrypt.wifi_permission, "green"))
                        else:
                            print("Wifi Permission Security Status ): " +
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
                                print("Wifi Permission for Security Status: " +
                                      colored(keycrypt.wifi_permission, "green"))
                            else:
                                print("Wifi Permission for Security Status: " +
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
                            input("Url: "))
                        account = Account(args["name"], username, password, url,
                                          category, keycrypt)
                        keycrypt.add_account(account)
                        account.show_account(False)
                        print(
                            colored(args["name"] + " Account Successfully Created", "green"))
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
                            for defined_attribute in ["Name", "Username", "Password", "Url", "Category"]:
                                if fuzz.ratio(attribute, defined_attribute) >= 70:
                                    attribute = defined_attribute
                            if attribute not in ["Name", "Username", "Password", "Url", "Category"]:
                                raise InvalidAttributeError
                            account.edit_account(attribute, keycrypt)
                            account.update_security_status(keycrypt)
                            account.show_account(
                                keycrypt.wifi_permission, args["password_visible"])
                            print(
                                colored(attribute + " Successfully Edited", "green"))
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
                except NoInternetError:
                    print(colored("No Internet Connection", "red"))
                except PathNotFoundError:
                    print(colored("Invalid Directory", "red"))
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
