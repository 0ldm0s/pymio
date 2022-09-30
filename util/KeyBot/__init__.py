# -*- coding: UTF-8 -*-
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher


class Core(object):
    @staticmethod
    def go_encrypt(msg: bytes, method, mode):
        cipher = Cipher(method, mode)
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()
        return ct

    @staticmethod
    def go_decrypt(ct: bytes, method, mode):
        cipher = Cipher(method, mode)
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    @staticmethod
    def go_encrypt_with_auth(msg, method, mode, add):
        cipher = Cipher(method, mode)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(add)
        ct = encryptor.update(msg) + encryptor.finalize()
        return ct, encryptor.tag

    @staticmethod
    def go_decrypt_with_auth(ct, method, mode, add):
        cipher = Cipher(method, mode)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(add)
        pl = decryptor.update(ct) + decryptor.finalize()
        return pl

    @staticmethod
    def pad(data, size=128):
        padder = padding.PKCS7(size).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        return padded_data

    @staticmethod
    def unpad(data, size=128):
        padder = padding.PKCS7(size).unpadder()
        unpadded_data = padder.update(data)
        unpadded_data += padder.finalize()
        return unpadded_data
