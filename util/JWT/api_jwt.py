# -*- coding: UTF-8 -*-
import orjson
import warnings
from calendar import timegm
from datetime import datetime, timedelta, timezone
from collections.abc import Mapping, Iterable
from typing import List, Optional, Dict, Any, Union
from .api_jws import PyJWS
from .warnings import RemovedInPyjwt3Warning
from .exceptions import MissingRequiredClaimError, InvalidIssuedAtError, ImmatureSignatureError, \
    ExpiredSignatureError, InvalidIssuerError, InvalidAudienceError


class JwtHelper:
    verify_signature: bool = True
    verify_exp: bool = True
    verify_nbf: bool = True
    verify_iat: bool = True
    verify_aud: bool = True
    verify_iss: bool = True
    require: List[str] = []

    def __init__(
            self, verify_signature: bool = True, verify_exp: bool = True, verify_nbf: bool = True,
            verify_iat: bool = True, verify_aud: bool = True, verify_iss: bool = True,
            require: Optional[List[str]] = None
    ):
        self.verify_signature = verify_signature
        self.verify_exp = verify_exp
        self.verify_nbf = verify_nbf
        self.verify_iat = verify_iat
        self.verify_aud = verify_aud
        self.verify_iss = verify_iss
        if require and isinstance(require, list):
            self.require = require

    @staticmethod
    def encode(
            payload: Dict[str, Any], key: str, algorithm: Optional[str] = "HS256",
            headers: Optional[Dict[str, Any]] = None,
    ) -> str:
        if not isinstance(payload, Mapping):
            raise TypeError(
                "Expecting a mapping object, as JWT only supports "
                "JSON objects as payloads."
            )
        payload = payload.copy()
        for time_claim in ["exp", "iat", "nbf"]:
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(payload[time_claim].utctimetuple())
        json_payload: bytes = orjson.dumps(payload)
        api_jws = PyJWS()
        return api_jws.encode(json_payload, key=key, algorithm=algorithm, headers=headers)

    @staticmethod
    def _validate_required_claims(payload, options):
        for claim in options["require"]:
            if payload.get(claim) is None:
                raise MissingRequiredClaimError(claim)

    @staticmethod
    def _validate_iat(payload, now, leeway):
        id(now), id(leeway)
        try:
            int(payload["iat"])
        except ValueError:
            raise InvalidIssuedAtError("Issued At claim (iat) must be an integer.")

    @staticmethod
    def _validate_nbf(payload, now, leeway):
        try:
            nbf = int(payload["nbf"])
        except ValueError:
            raise orjson.JSONDecodeError("Not Before claim (nbf) must be an integer.")

        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    @staticmethod
    def _validate_exp(payload, now, leeway):
        try:
            exp = int(payload["exp"])
        except ValueError:
            raise orjson.JSONDecodeError("Expiration Time claim (exp) must be an" " integer.")

        if exp <= (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    @staticmethod
    def _validate_iss(payload, issuer):
        if issuer is None:
            return

        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        if payload["iss"] != issuer:
            raise InvalidIssuerError("Invalid issuer")

    @staticmethod
    def _validate_aud(payload, audience):
        if audience is None:
            if "aud" not in payload or not payload["aud"]:
                return
            raise InvalidAudienceError("Invalid audience")

        if "aud" not in payload or not payload["aud"]:
            raise MissingRequiredClaimError("aud")

        audience_claims = payload["aud"]

        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, str) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")

        if isinstance(audience, str):
            audience = [audience]

        if all(aud not in audience_claims for aud in audience):
            raise InvalidAudienceError("Invalid audience")

    def _validate_claims(self, payload, options, audience=None, issuer=None, leeway=0):
        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()

        if audience is not None and not isinstance(audience, (str, Iterable)):
            raise TypeError("audience must be a string, iterable or None")

        self._validate_required_claims(payload, options)

        now = timegm(datetime.now(tz=timezone.utc).utctimetuple())

        if "iat" in payload and options["verify_iat"]:
            self._validate_iat(payload, now, leeway)

        if "nbf" in payload and options["verify_nbf"]:
            self._validate_nbf(payload, now, leeway)

        if "exp" in payload and options["verify_exp"]:
            self._validate_exp(payload, now, leeway)

        if options["verify_iss"]:
            self._validate_iss(payload, issuer)

        if options["verify_aud"]:
            self._validate_aud(payload, audience)

    def decode_complete(
            self, jwt: str, key: str = "", algorithms: Optional[List[str]] = None,
            options: Optional[Dict[str, Any]] = None, verify: Optional[bool] = None,
            detached_payload: Optional[bytes] = None, audience: Optional[Union[str, Iterable[str]]] = None,
            issuer: Optional[str] = None, leeway: Union[int, float, timedelta] = 0, **kwargs,
    ) -> Dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
            )
        options = dict(options or {})
        options.setdefault("verify_signature", True)
        if verify is not None and verify != options["verify_signature"]:
            warnings.warn(
                "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer. "
                "The equivalent is setting `verify_signature` to False in the `options` dictionary. "
                "This invocation has a mismatch between the kwarg and the option entry.",
                category=DeprecationWarning,
            )
        if not options["verify_signature"]:
            options.setdefault("verify_exp", False)
            options.setdefault("verify_nbf", False)
            options.setdefault("verify_iat", False)
            options.setdefault("verify_aud", False)
            options.setdefault("verify_iss", False)

        if options["verify_signature"] and not algorithms:
            raise orjson.JSONDecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        api_jws = PyJWS()
        decoded = api_jws.decode_complete(
            jwt,
            key=key,
            algorithms=algorithms,
            options=options,
            detached_payload=detached_payload,
        )
        try:
            payload = orjson.loads(decoded["payload"])
        except ValueError as e:
            raise orjson.JSONDecodeError(f"Invalid payload string: {e}")
        if not isinstance(payload, dict):
            raise orjson.JSONDecodeError("Invalid payload string: must be a json object")

        options.update({
            "verify_signature": self.verify_signature,
            "verify_exp": self.verify_exp,
            "verify_nbf": self.verify_nbf,
            "verify_iat": self.verify_iat,
            "verify_aud": self.verify_aud,
            "verify_iss": self.verify_iss,
            "require": self.require,
        })
        self._validate_claims(
            payload, options, audience=audience, issuer=issuer, leeway=leeway
        )

        decoded["payload"] = payload
        return decoded

    def decode(
            self, jwt: str, key: str = "", algorithms: Optional[List[str]] = None,
            options: Optional[Dict[str, Any]] = None, verify: Optional[bool] = None,
            detached_payload: Optional[bytes] = None, audience: Optional[Union[str, Iterable[str]]] = None,
            issuer: Optional[str] = None, leeway: Union[int, float, timedelta] = 0, **kwargs,
    ) -> Dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
            )
        decoded = self.decode_complete(
            jwt,
            key,
            algorithms,
            options,
            verify=verify,
            detached_payload=detached_payload,
            audience=audience,
            issuer=issuer,
            leeway=leeway,
        )
        return decoded["payload"]
