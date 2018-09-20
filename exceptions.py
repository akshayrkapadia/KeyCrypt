class AccountDoesNotExistError(Exception):
    pass


class AccountNotConfiguredError(Exception):
    def __init__(self, message, account):
        Exception.__init__(self, message)
        self.message = message
        self.account = account


class InvalidCategoryError(Exception):
    pass


class InvalidAttributeError(Exception):
    pass


class GPGError(Exception):
    pass


class NoInternetError(Exception):
    pass


class InvalidSettingError(Exception):
    pass
