# -*- coding: UTF-8 -*-
import hmac
import orjson
import hashlib
from typing import Dict
from .exceptions import InvalidKeyError
from mio.util.Helper import force_bytes, is_pem_format, is_ssh_key, base64url_encode, base64url_decode, \
    to_base64url_uint, from_base64url_uint, der_to_raw_signature, raw_to_der_signature

requires_cryptography = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES521",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
}

try:
    import cryptography.exceptions
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PrivateKey,
        Ed448PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPrivateNumbers,
        RSAPublicKey,
        RSAPublicNumbers,
        rsa_crt_dmp1,
        rsa_crt_dmq1,
        rsa_crt_iqmp,
        rsa_recover_prime_factors,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )

    has_crypto = True
except ModuleNotFoundError:
    has_crypto = False


class Algorithm:
    def prepare_key(self, key):
        raise NotImplementedError

    def sign(self, msg, key):
        raise NotImplementedError

    def verify(self, msg, key, sig):
        raise NotImplementedError

    @staticmethod
    def to_jwk(key_obj):
        raise NotImplementedError

    @staticmethod
    def from_jwk(jwk):
        raise NotImplementedError


class NoneAlgorithm(Algorithm):
    def prepare_key(self, key):
        if key == "":
            key = None

        if key is not None:
            raise InvalidKeyError('When alg = "none", key value must be None.')

        return key

    def sign(self, msg, key):
        return b""

    def verify(self, msg, key, sig):
        return False

    @staticmethod
    def to_jwk(key_obj):
        return b""

    @staticmethod
    def from_jwk(jwk):
        return b""


class HMACAlgorithm(Algorithm):
    SHA256 = hashlib.sha256
    SHA384 = hashlib.sha384
    SHA512 = hashlib.sha512

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_key(self, key):
        key = force_bytes(key)

        if is_pem_format(key) or is_ssh_key(key):
            raise InvalidKeyError(
                "The specified key is an asymmetric key or x509 certificate and"
                " should not be used as an HMAC secret."
            )

        return key

    def sign(self, msg, key):
        return hmac.new(key, msg, self.hash_alg).digest()

    def verify(self, msg, key, sig):
        return hmac.compare_digest(sig, self.sign(msg, key))

    @staticmethod
    def to_jwk(key_obj):
        obj: Dict = {
            "k": base64url_encode(force_bytes(key_obj)).decode(),
            "kty": "oct",
        }
        return orjson.dumps(obj)

    @staticmethod
    def from_jwk(jwk):
        obj: Dict
        try:
            if isinstance(jwk, str):
                obj = orjson.loads(jwk)
            elif isinstance(jwk, dict):
                obj = jwk
            else:
                raise ValueError
        except ValueError:
            raise InvalidKeyError("Key is not valid JSON")

        if obj.get("kty") != "oct":
            raise InvalidKeyError("Not an HMAC key")

        return base64url_decode(obj["k"])


if has_crypto:
    class RSAAlgorithm(Algorithm):
        SHA256 = hashes.SHA256
        SHA384 = hashes.SHA384
        SHA512 = hashes.SHA512

        def __init__(self, hash_alg):
            self.hash_alg = hash_alg

        def prepare_key(self, key):
            if isinstance(key, (RSAPrivateKey, RSAPublicKey)):
                return key

            if not isinstance(key, (bytes, str)):
                raise TypeError("Expecting a PEM-formatted key.")

            key = force_bytes(key)
            try:
                if key.startswith(b"ssh-rsa"):
                    key = load_ssh_public_key(key)
                else:
                    key = load_pem_private_key(key, password=None)
            except ValueError:
                key = load_pem_public_key(key)
            return key

        def sign(self, msg, key):
            return key.sign(msg, padding.PKCS1v15(), self.hash_alg())

        def verify(self, msg, key, sig):
            try:
                key.verify(sig, msg, padding.PKCS1v15(), self.hash_alg())
                return True
            except InvalidSignature:
                return False

        @staticmethod
        def to_jwk(key_obj):
            obj: Dict
            if getattr(key_obj, "private_numbers", None):
                numbers = key_obj.private_numbers()
                obj = {
                    "kty": "RSA",
                    "key_ops": ["sign"],
                    "n": to_base64url_uint(numbers.public_numbers.n).decode(),
                    "e": to_base64url_uint(numbers.public_numbers.e).decode(),
                    "d": to_base64url_uint(numbers.d).decode(),
                    "p": to_base64url_uint(numbers.p).decode(),
                    "q": to_base64url_uint(numbers.q).decode(),
                    "dp": to_base64url_uint(numbers.dmp1).decode(),
                    "dq": to_base64url_uint(numbers.dmq1).decode(),
                    "qi": to_base64url_uint(numbers.iqmp).decode(),
                }
            elif getattr(key_obj, "verify", None):
                numbers = key_obj.public_numbers()
                obj = {
                    "kty": "RSA",
                    "key_ops": ["verify"],
                    "n": to_base64url_uint(numbers.n).decode(),
                    "e": to_base64url_uint(numbers.e).decode(),
                }
            else:
                raise InvalidKeyError("Not a public or private key")

            return orjson.dumps(obj)

        @staticmethod
        def from_jwk(jwk):
            obj: Dict
            try:
                if isinstance(jwk, str):
                    obj = orjson.loads(jwk)
                elif isinstance(jwk, dict):
                    obj = jwk
                else:
                    raise ValueError
            except ValueError:
                raise InvalidKeyError("Key is not valid JSON")

            if obj.get("kty") != "RSA":
                raise InvalidKeyError("Not an RSA key")

            if "d" in obj and "e" in obj and "n" in obj:
                if "oth" in obj:
                    raise InvalidKeyError(
                        "Unsupported RSA private key: > 2 primes not supported"
                    )
                other_props = ["p", "q", "dp", "dq", "qi"]
                props_found = [prop in obj for prop in other_props]
                any_props_found = any(props_found)

                if any_props_found and not all(props_found):
                    raise InvalidKeyError(
                        "RSA key must include all parameters if any are present besides d"
                    )
                public_numbers = RSAPublicNumbers(
                    from_base64url_uint(obj["e"]),
                    from_base64url_uint(obj["n"]),
                )

                if any_props_found:
                    numbers = RSAPrivateNumbers(
                        d=from_base64url_uint(obj["d"]),
                        p=from_base64url_uint(obj["p"]),
                        q=from_base64url_uint(obj["q"]),
                        dmp1=from_base64url_uint(obj["dp"]),
                        dmq1=from_base64url_uint(obj["dq"]),
                        iqmp=from_base64url_uint(obj["qi"]),
                        public_numbers=public_numbers,
                    )
                else:
                    d = from_base64url_uint(obj["d"])
                    p, q = rsa_recover_prime_factors(
                        public_numbers.n, d, public_numbers.e
                    )

                    numbers = RSAPrivateNumbers(
                        d=d,
                        p=p,
                        q=q,
                        dmp1=rsa_crt_dmp1(d, p),
                        dmq1=rsa_crt_dmq1(d, q),
                        iqmp=rsa_crt_iqmp(p, q),
                        public_numbers=public_numbers,
                    )
                return numbers.private_key()
            elif "n" in obj and "e" in obj:
                numbers = RSAPublicNumbers(
                    from_base64url_uint(obj["e"]),
                    from_base64url_uint(obj["n"]),
                )
                return numbers.public_key()
            else:
                raise InvalidKeyError("Not a public or private key")


    class ECAlgorithm(Algorithm):
        SHA256 = hashes.SHA256
        SHA384 = hashes.SHA384
        SHA512 = hashes.SHA512

        def __init__(self, hash_alg):
            self.hash_alg = hash_alg

        def prepare_key(self, key):
            if isinstance(key, (EllipticCurvePrivateKey, EllipticCurvePublicKey)):
                return key

            if not isinstance(key, (bytes, str)):
                raise TypeError("Expecting a PEM-formatted key.")

            key = force_bytes(key)
            try:
                if key.startswith(b"ecdsa-sha2-"):
                    key = load_ssh_public_key(key)
                else:
                    key = load_pem_public_key(key)
            except ValueError:
                key = load_pem_private_key(key, password=None)

            if not isinstance(key, (EllipticCurvePrivateKey, EllipticCurvePublicKey)):
                raise InvalidKeyError(
                    "Expecting a EllipticCurvePrivateKey/EllipticCurvePublicKey. "
                    "Wrong key provided for ECDSA algorithms"
                )
            return key

        def sign(self, msg, key):
            der_sig = key.sign(msg, ec.ECDSA(self.hash_alg()))
            return der_to_raw_signature(der_sig, key.curve)

        def verify(self, msg, key, sig):
            try:
                der_sig = raw_to_der_signature(sig, key.curve)
            except ValueError:
                return False

            try:
                if isinstance(key, EllipticCurvePrivateKey):
                    key = key.public_key()
                key.verify(der_sig, msg, ec.ECDSA(self.hash_alg()))
                return True
            except InvalidSignature:
                return False

        @staticmethod
        def to_jwk(key_obj):
            if isinstance(key_obj, EllipticCurvePrivateKey):
                public_numbers = key_obj.public_key().public_numbers()
            elif isinstance(key_obj, EllipticCurvePublicKey):
                public_numbers = key_obj.public_numbers()
            else:
                raise InvalidKeyError("Not a public or private key")

            if isinstance(key_obj.curve, ec.SECP256R1):
                crv = "P-256"
            elif isinstance(key_obj.curve, ec.SECP384R1):
                crv = "P-384"
            elif isinstance(key_obj.curve, ec.SECP521R1):
                crv = "P-521"
            elif isinstance(key_obj.curve, ec.SECP256K1):
                crv = "secp256k1"
            else:
                raise InvalidKeyError(f"Invalid curve: {key_obj.curve}")

            obj: Dict = {
                "kty": "EC",
                "crv": crv,
                "x": to_base64url_uint(public_numbers.x).decode(),
                "y": to_base64url_uint(public_numbers.y).decode(),
            }

            if isinstance(key_obj, EllipticCurvePrivateKey):
                obj["d"] = to_base64url_uint(
                    key_obj.private_numbers().private_value
                ).decode()

            return orjson.dumps(obj)

        @staticmethod
        def from_jwk(jwk):
            obj: Dict
            try:
                if isinstance(jwk, str):
                    obj = orjson.loads(jwk)
                elif isinstance(jwk, dict):
                    obj = jwk
                else:
                    raise ValueError
            except ValueError:
                raise InvalidKeyError("Key is not valid JSON")

            if obj.get("kty") != "EC":
                raise InvalidKeyError("Not an Elliptic curve key")

            if "x" not in obj or "y" not in obj:
                raise InvalidKeyError("Not an Elliptic curve key")

            x = base64url_decode(obj.get("x"))
            y = base64url_decode(obj.get("y"))

            curve = obj.get("crv")
            if curve == "P-256":
                if len(x) == len(y) == 32:
                    curve_obj = ec.SECP256R1()
                else:
                    raise InvalidKeyError("Coords should be 32 bytes for curve P-256")
            elif curve == "P-384":
                if len(x) == len(y) == 48:
                    curve_obj = ec.SECP384R1()
                else:
                    raise InvalidKeyError("Coords should be 48 bytes for curve P-384")
            elif curve == "P-521":
                if len(x) == len(y) == 66:
                    curve_obj = ec.SECP521R1()
                else:
                    raise InvalidKeyError("Coords should be 66 bytes for curve P-521")
            elif curve == "secp256k1":
                if len(x) == len(y) == 32:
                    curve_obj = ec.SECP256K1()
                else:
                    raise InvalidKeyError(
                        "Coords should be 32 bytes for curve secp256k1"
                    )
            else:
                raise InvalidKeyError(f"Invalid curve: {curve}")

            public_numbers = ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(x, byteorder="big"),
                y=int.from_bytes(y, byteorder="big"),
                curve=curve_obj,
            )

            if "d" not in obj:
                return public_numbers.public_key()

            d = base64url_decode(obj.get("d"))
            if len(d) != len(x):
                raise InvalidKeyError(
                    "D should be {} bytes for curve {}", len(x), curve
                )

            return ec.EllipticCurvePrivateNumbers(
                int.from_bytes(d, byteorder="big"), public_numbers
            ).private_key()


    class RSAPSSAlgorithm(RSAAlgorithm):
        def sign(self, msg, key):
            return key.sign(
                msg,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_alg()),
                    salt_length=self.hash_alg.digest_size,
                ),
                self.hash_alg(),
            )

        def verify(self, msg, key, sig):
            try:
                key.verify(
                    sig,
                    msg,
                    padding.PSS(
                        mgf=padding.MGF1(self.hash_alg()),
                        salt_length=self.hash_alg.digest_size,
                    ),
                    self.hash_alg(),
                )
                return True
            except InvalidSignature:
                return False


    class OKPAlgorithm(Algorithm):
        def __init__(self, **kwargs):
            pass

        def prepare_key(self, key):
            if isinstance(key, (bytes, str)):
                if isinstance(key, str):
                    key = key.encode("UTF-8")
                str_key = key.decode("UTF-8")

                if "-----BEGIN PUBLIC" in str_key:
                    key = load_pem_public_key(key)
                elif "-----BEGIN PRIVATE" in str_key:
                    key = load_pem_private_key(key, password=None)
                elif str_key[0:4] == "ssh-":
                    key = load_ssh_public_key(key)
            if not isinstance(
                    key,
                    (Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey),
            ):
                raise InvalidKeyError(
                    "Expecting a EllipticCurvePrivateKey/EllipticCurvePublicKey. "
                    "Wrong key provided for EdDSA algorithms"
                )
            return key

        def sign(self, msg, key):
            msg = bytes(msg, "UTF-8") if type(msg) is not bytes else msg
            return key.sign(msg)

        def verify(self, msg, key, sig):
            try:
                msg = bytes(msg, "UTF-8") if type(msg) is not bytes else msg
                sig = bytes(sig, "UTF-8") if type(sig) is not bytes else sig

                if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
                    key = key.public_key()
                key.verify(sig, msg)
                return True
            except cryptography.exceptions.InvalidSignature:
                return False

        @staticmethod
        def to_jwk(key_obj):
            if isinstance(key_obj, (Ed25519PublicKey, Ed448PublicKey)):
                x = key_obj.public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw,
                )
                crv = "Ed25519" if isinstance(key_obj, Ed25519PublicKey) else "Ed448"
                return orjson.dumps(
                    {
                        "x": base64url_encode(force_bytes(x)).decode(),
                        "kty": "OKP",
                        "crv": crv,
                    }
                )
            if isinstance(key_obj, (Ed25519PrivateKey, Ed448PrivateKey)):
                d = key_obj.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption(),
                )

                x = key_obj.public_key().public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw,
                )

                crv = "Ed25519" if isinstance(key_obj, Ed25519PrivateKey) else "Ed448"
                return orjson.dumps(
                    {
                        "x": base64url_encode(force_bytes(x)).decode(),
                        "d": base64url_encode(force_bytes(d)).decode(),
                        "kty": "OKP",
                        "crv": crv,
                    }
                )
            raise InvalidKeyError("Not a public or private key")

        @staticmethod
        def from_jwk(jwk):
            obj: Dict
            try:
                if isinstance(jwk, str):
                    obj = orjson.loads(jwk)
                elif isinstance(jwk, dict):
                    obj = jwk
                else:
                    raise ValueError
            except ValueError:
                raise InvalidKeyError("Key is not valid JSON")

            if obj.get("kty") != "OKP":
                raise InvalidKeyError("Not an Octet Key Pair")

            curve = obj.get("crv")
            if curve != "Ed25519" and curve != "Ed448":
                raise InvalidKeyError(f"Invalid curve: {curve}")

            if "x" not in obj:
                raise InvalidKeyError('OKP should have "x" parameter')
            x = base64url_decode(obj.get("x"))

            try:
                if "d" not in obj:
                    if curve == "Ed25519":
                        return Ed25519PublicKey.from_public_bytes(x)
                    return Ed448PublicKey.from_public_bytes(x)
                d = base64url_decode(obj.get("d"))
                if curve == "Ed25519":
                    return Ed25519PrivateKey.from_private_bytes(d)
                return Ed448PrivateKey.from_private_bytes(d)
            except ValueError as err:
                raise InvalidKeyError("Invalid key parameter") from err


def get_default_algorithms():
    default_algorithms = {
        "none": NoneAlgorithm(),
        "HS256": HMACAlgorithm(HMACAlgorithm.SHA256),
        "HS384": HMACAlgorithm(HMACAlgorithm.SHA384),
        "HS512": HMACAlgorithm(HMACAlgorithm.SHA512),
    }
    if has_crypto:
        default_algorithms.update(
            {
                "RS256": RSAAlgorithm(RSAAlgorithm.SHA256),
                "RS384": RSAAlgorithm(RSAAlgorithm.SHA384),
                "RS512": RSAAlgorithm(RSAAlgorithm.SHA512),
                "ES256": ECAlgorithm(ECAlgorithm.SHA256),
                "ES256K": ECAlgorithm(ECAlgorithm.SHA256),
                "ES384": ECAlgorithm(ECAlgorithm.SHA384),
                "ES521": ECAlgorithm(ECAlgorithm.SHA512),
                "ES512": ECAlgorithm(
                    ECAlgorithm.SHA512
                ),  # Backward compat for #219 fix
                "PS256": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
                "PS384": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
                "PS512": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
                "EdDSA": OKPAlgorithm(),
            }
        )
    return default_algorithms
