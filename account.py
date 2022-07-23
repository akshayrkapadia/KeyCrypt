import getpass
import datetime
import requests
from hashlib import sha1
from fuzzywuzzy import fuzz
from termcolor import colored
from selenium import webdriver
from dateutil.relativedelta import relativedelta
from selenium.webdriver.firefox.options import Options
from keycrypt import *


class Account:
    def __init__(self, name, username, password, url, category, keycrypt):
        self.name = name
        self.username = username
        self.password = password
        self.url = url
        self.category = category
        self.account_id = hash(name + username)
        self.date_modified = datetime.date.today()
        self.date_password_modified = datetime.date.today()
        self.password_expiration_date = self.date_modified + \
            relativedelta(months=+3)
        self.autologin = False
        self.username_id = None
        self.password_id = None
        self.security_status = None
        self.security_status_description = None
        self.breach_date = None
        self.breach_domain = None
        self.password_strength = KeyCrypt.check_password_strength(
            self.password)
        self.account_hash = "{}{}{}".format(name, username, password)
        self.update_security_status(keycrypt)

    # Sets up the correct username and password element ids for autologin
    def configure_autologin(self):
        print(colored("Gathering Website Data...", "red"))
        options = Options()
        options.add_argument("--headless")
        browser = webdriver.Firefox(firefox_options=options)
        browser.implicitly_wait(15)
        browser.get(self.url)
        elements = browser.find_elements_by_xpath("//*[@id]")
        element_attributes = []
        for element in elements:
            element_attributes.append(element.get_attribute("id"))
        browser.delete_all_cookies()
        browser.close()

        username_search_terms = ["username", "login", "name", "email"]
        password_search_terms = ["password", "pass", "login"]
        username_elements = ["Manuel Entry"]
        password_elements = ["Manuel Entry"]

        # Filters the element ids according to the specified search terms
        for element_attribute in element_attributes:
            for search_term in username_search_terms:
                if fuzz.partial_ratio(element_attribute, search_term) > 70:
                    username_elements.insert(0, element_attribute)
            for search_term in password_search_terms:
                if fuzz.partial_ratio(element_attribute, search_term) > 70:
                    password_elements.insert(0, element_attribute)

        print(username_elements)
        print(password_elements)

        # Prompts the user the select the correct id for the username and password
        for attribute in ["Username", "Password"]:
            field_elements = username_elements if (
                attribute == "Username") else password_elements
            print(colored("Select The Element ID That Represents The " +
                          attribute + " Field", "red"))
            for element_attribute, i in zip(field_elements, range(len(field_elements))):
                print(str(i) + ") " + colored(field_elements[i], "blue"))
            element_attribute = "Manuel Entry"
            element_index = int(input("Select An Element ID Number: "))
            if element_index not in range(len(field_elements)):
                raise ValueError
            elif field_elements[element_index] == "Manuel Entry":
                element_attribute = str(input(attribute + " Element ID: "))
            else:
                element_attribute = field_elements[element_index]
            if attribute == "Username":
                self.username_id = element_attribute
            else:
                self.password_id = element_attribute

    # Prints all the account details
    def show_account(self, wifi_permission, password_visible=False):
        print(colored(self.name, "red"))
        print("  Username: " + colored(self.username, "blue"))
        if password_visible:
            print("  Password: " + colored(self.password, "blue"))
        if (self.password_strength == "Very Strong" or self.password_strength == "Strong"):
            print("  Password Strength: " +
                  colored(self.password_strength, "green"))
        elif self.password_strength == "Medium":
            print("  Password Strength: " +
                  colored(self.password_strength, "yellow"))
        elif (self.password_strength == "Weak" or self.password_strength == "Very Weak"):
            print("  Password Strength: " +
                  colored(self.password_strength, "red"))
        if self.url != "":
            print("  Url: " + colored(self.url, "blue"))
        print("  Category: " + colored(self.category, "blue"))
        print("  Date Modified: " + colored(str(self.date_modified), "blue"))
        if (self.password_expiration_date - datetime.date.today()) <= datetime.timedelta(days=0):
            print("  Password Expiration: " +
                  colored(str(self.password_expiration_date), "red"))
        elif (self.password_expiration_date - datetime.date.today()) <= datetime.timedelta(days=10):
            print("  Password Expiration: " +
                  colored(str(self.password_expiration_date), "yellow"))
        else:
            print("  Password Expiration: " +
                  colored(str(self.password_expiration_date), "green"))
        print("  Autologin: " + colored(str(self.autologin), "blue"))
        if wifi_permission:
            if KeyCrypt.wifi_enabled(wifi_permission):
                if self.security_status == "At Risk":
                    print("  Security Status: " +
                          colored(self.security_status, "yellow"))
                    print("  Security Description: " +
                          colored(self.security_status_description, "red"))
                elif (self.security_status == "Breached" or self.security_status == "Potentially Breached"):
                    print("  Security Status: " +
                          colored(self.security_status, "red"))
                    print("  Security Description: " +
                          colored(self.security_status_description, "red"))
                    print("  Breach Date: " + colored(self.breach_date, "red"))
                    print("  Breach Domain: " +
                          colored(self.breach_domain, "red"))
                elif self.security_status == "Secure":
                    print("  Security Status: " +
                          colored(self.security_status, "green"))
            else:
                print("  Security Status: " + colored("No Internet", "red"))

    # Edits the specified account attribute
    def edit_account(self, attribute, keycrypt):
        if attribute == "Autologin":
            if not self.autologin:
                self.autologin = True
            self.autologin = False if (
                str(input("Disable Autologin (y/N): ")).lower() in ["y", "yes"]) else True
            if self.autologin:
                if KeyCrypt.wifi_enabled(keycrypt.wifi_permission):
                    self.configure_autologin()
                else:
                    raise NoInternetError
        elif attribute == "Password":
            # Asks if the password should randomly be generated
            is_random = False if (str(input("Random Password (Y/n): ")
                                      ).lower() in ["n", "no"]) else True
            # Length of random password if needed
            length = int(input("Length: ")) if is_random else None
            new_value = KeyCrypt.generate_password(
                length) if is_random else getpass.getpass("Password: ")
            self.password = new_value
            self.password_expiration_date = datetime.date.today() + relativedelta(months=+
                                                                                  3)  # Sets the new password expiration date
            self.password_strength = KeyCrypt.check_password_strength(
                self.password)
        elif attribute == "Category":
            new_value = str(
                input("Category (Email, Web, Social, Banking, Computer, Other): ")).lower().capitalize()
            for defined_category in ["Email", "Web", "Social", "Banking", "Computer", "Other"]:
                if fuzz.ratio(new_value, defined_category) >= 70:
                    new_value = defined_category
            if new_value not in ["Email", "Web", "Social", "Banking", "Computer", "Other"]:
                raise InvalidCategoryError
            self.category = new_value
        else:
            new_value = str(input("New Value: "))
            if attribute == "Name":
                self.name = new_value
            elif attribute == "Username":
                self.username = new_value
            elif attribute == "Url":
                self.url = new_value
        self.date_modified = datetime.date.today()
        self.update_security_status(keycrypt)

    # Checks haveibeenpwned.com for your password in the pwned password database
    def password_pwned(self):
        hashed_password = sha1(self.password.encode('utf-8')).hexdigest()
        prefix = hashed_password[:5]
        user_agent = {"User-Agent": "KeyCrypt"}
        pwned_passwords = 'https://api.pwnedpasswords.com/range/{}'
        matches = requests.get(pwned_passwords.format(prefix), user_agent).text
        for line in iter(matches.splitlines()):
            if line[:35].lower() == hashed_password[5:]:
                return True
        return False

    # Checks if the password is being reused
    def password_duplicate(self, keycrypt):
        for account in keycrypt.accounts:
            if (account != self and account.password == self.password):
                return True
        return False

    # Tests the password to see if it is expired, weak, duplicated, or pwned
    def check_password_security(self, keycrypt, online=False):
        password_security_status = None
        if ((self.password_expiration_date - datetime.date.today()) <= datetime.timedelta(days=0)):
            password_security_status = "Password Expired"
        if (KeyCrypt.check_password_strength(self.password) == "Weak" or KeyCrypt.check_password_strength(self.password) == "Very Weak"):
            if password_security_status is None:
                password_security_status = "Password Weak"
            else:
                password_security_status = "Password Expired & Weak"
        if self.password_duplicate(keycrypt):
            if password_security_status is None:
                password_security_status = "Password Duplicated"
            elif password_security_status == "Password Weak":
                password_security_status = "Password Weak & Duplicated"
            elif password_security_status == "Password Expired":
                password_security_status = "Password Expired & Duplicated"
            else:
                password_security_status = "Password Expired, Weak, & Duplicated"
        if online:
            if self.password_pwned():
                if password_security_status == "Password Expired":
                    password_security_status = "Password Expired & Pwned"
                elif password_security_status == "Password Weak":
                    password_security_status = "Password Weak & Pwned"
                elif password_security_status == "Password Duplicated":
                    password_security_status = "Password Duplicated & Pwned"
                elif password_security_status == "Password Expired & Weak":
                    password_security_status = "Password Expired, Weak, & Pwned"
                elif password_security_status == "Password Expired & Duplicated":
                    password_security_status = "Password Expired, Duplicated, & Pwned"
                elif password_security_status == "Password Weak & Duplicated":
                    password_security_status = "Password Weak, Duplicated, & Pwned"
                else:
                    password_security_status = "Password Expired, Weak, Duplicated, & Pwned"
        return password_security_status

    # Updates the security status by looking at account breaches and password security
    def update_security_status(self, keycrypt):
        self.security_status_description = None
        self.breached_date = None
        self.breach_domain = None
        self.breach_description = None
        if KeyCrypt.wifi_enabled(keycrypt.wifi_permission):
            self.security_status_description = self.check_password_security(
                keycrypt, True)
            self.security_status = "Secure" if self.security_status_description is None else "At Risk"
            user_agent = {"User-Agent": "KeyCrypt"}
            req = requests.get("https://haveibeenpwned.com/api/v2/breach/" +
                               self.name, headers=user_agent)  # Gets all the breach data
            if req.status_code == 200:  # Data Successfully retrieved
                breach_data = req.json()
                breach_date = datetime.datetime.strptime(
                    breach_data["BreachDate"], "%Y-%M-%d").date()
                # Compares breach date and last time password was changed
                if (self.date_password_modified - breach_date) <= datetime.timedelta(days=0):
                    # Checks if the data is verified
                    self.security_status = "Breached" if breach_data[
                        "isVerified"] else "Potentially Breached"
                    self.security_status_description = "Breach Found On haveibeenpwned.com" if self.security_status_description is None else "Breach Found On haveibeenpwned.com. " + self.security_status_description
                    self.breach_date = breach_date
                    self.breach_domain = breach_data["Domain"]
        else:
            self.security_status_description = self.check_password_security(
                keycrypt)
            self.security_status = "Secure" if self.security_status_description is None else "At Risk"

    # Logs into the website using the selenium webdriver
    def login(self):
        profile = webdriver.FirefoxProfile()
        profile.set_preference("places.history.enabled", False)
        profile.set_preference("privacy.clearOnShutdown.offlineApps", True)
        profile.set_preference("privacy.clearOnShutdown.passwords", True)
        profile.set_preference("privacy.clearOnShutdown.siteSettings", True)
        profile.set_preference("privacy.sanitize.sanitizeOnShutdown", True)
        profile.set_preference("signon.rememberSignons", False)
        profile.set_preference("network.cookie.lifetimePolicy", 2)
        profile.set_preference("network.dns.disablePrefetch", True)
        profile.set_preference("network.http.sendRefererHeader", 0)
        profile.set_preference("javascript.enabled", False)
        browser = webdriver.Firefox(profile)  # Uses firefox browser
        browser.implicitly_wait(15)
        browser.maximize_window()
        browser.get(self.url)
        username_field = browser.find_element_by_id(self.username_id)
        username_field.clear()
        username_field.send_keys(self.username)
        password_field = browser.find_element_by_id(self.password_id)
        password_field.clear()
        password_field.send_keys(self.password)
        password_field.submit()

    # Tests to see if another account is the same as this accounts
    def equals(self, other_account):
        return True if (self.account_hash == other_account.account_hash) else False
