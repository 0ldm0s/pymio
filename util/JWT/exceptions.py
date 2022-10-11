# -*- coding: UTF-8 -*
class PyJWTError(Exception):
    pass


class InvalidKeyError(PyJWTError):
    pass


class InvalidTokenError(PyJWTError):
    pass


class DecodeError(InvalidTokenError):
    pass


class InvalidSignatureError(DecodeError):
    pass


class InvalidAlgorithmError(InvalidTokenError):
    pass


class MissingRequiredClaimError(InvalidTokenError):
    def __init__(self, claim):
        self.claim = claim

    def __str__(self):
        return f'Token is missing the "{self.claim}" claim'


class InvalidIssuedAtError(InvalidTokenError):
    pass


class ImmatureSignatureError(InvalidTokenError):
    pass


class ExpiredSignatureError(InvalidTokenError):
    pass


class InvalidIssuerError(InvalidTokenError):
    pass


class InvalidAudienceError(InvalidTokenError):
    pass
