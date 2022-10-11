# -*- coding: UTF-8 -*-
import orjson
import binascii
import warnings
from typing import Any, Optional, Dict, List, Union, Tuple
from mio.util.Helper import base64url_encode, base64url_decode
from .algorithms import get_default_algorithms, has_crypto, Algorithm, requires_cryptography
from .exceptions import InvalidTokenError, InvalidSignatureError, InvalidAlgorithmError
from .warnings import RemovedInPyjwt3Warning


class PyJWS:
    header_typ: bool = "JWT"

    @staticmethod
    def _get_default_options() -> dict[str, bool]:
        return {"verify_signature": True}

    def __init__(self, algorithms=None, options=None) -> None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = set(algorithms) if algorithms is not None else set(self._algorithms)
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]

        if options is None:
            options = {}
        self.options = {**self._get_default_options(), **options}

    @staticmethod
    def _validate_kid(kid: str) -> None:
        if not isinstance(kid, str):
            raise InvalidTokenError("Key ID header parameter must be a string")

    def _validate_headers(self, headers: dict[str, Any]) -> None:
        if "kid" in headers:
            self._validate_kid(headers["kid"])

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        try:
            return self._algorithms[alg_name]
        except KeyError as e:
            if not has_crypto and alg_name in requires_cryptography:
                raise NotImplementedError(
                    f"Algorithm '{alg_name}' could not be found. Do you have cryptography installed?"
                ) from e
            raise NotImplementedError("Algorithm not supported") from e

    def encode(
            self, payload: bytes, key: str, algorithm: Optional[str] = "HS256",
            headers: Optional[Dict[str, Any]] = None, is_payload_detached: bool = False,
    ) -> str:
        segments = []
        algorithm_: str = algorithm if algorithm is not None else "none"
        if headers:
            headers_alg = headers.get("alg")
            if headers_alg:
                algorithm_ = headers["alg"]

            headers_b64 = headers.get("b64")
            if headers_b64 is False:
                is_payload_detached = True
        header: Dict[str, Any] = {"typ": self.header_typ, "alg": algorithm_}
        if headers:
            self._validate_headers(headers)
            header.update(headers)

        if not header["typ"]:
            del header["typ"]

        if is_payload_detached:
            header["b64"] = False
        elif "b64" in header:
            del header["b64"]

        json_header = orjson.dumps(header, option=orjson.OPT_SORT_KEYS)

        segments.append(base64url_encode(json_header))

        if is_payload_detached:
            msg_payload = payload
        else:
            msg_payload = base64url_encode(payload)
        segments.append(msg_payload)

        signing_input = b".".join(segments)
        alg_obj = self.get_algorithm_by_name(algorithm_)
        key = alg_obj.prepare_key(key)
        signature = alg_obj.sign(signing_input, key)

        segments.append(base64url_encode(signature))

        if is_payload_detached:
            segments[1] = b""
        encoded_string = b".".join(segments)

        return encoded_string.decode("UTF-8")

    @staticmethod
    def _load(jwt: Union[str, bytes]) -> Tuple[bytes, bytes, dict, bytes]:
        if isinstance(jwt, str):
            jwt = jwt.encode("UTF-8")

        if not isinstance(jwt, bytes):
            raise orjson.JSONDecodeError(f"Invalid token type. Token must be a {bytes}")

        try:
            signing_input, crypto_segment = jwt.rsplit(b".", 1)
            header_segment, payload_segment = signing_input.split(b".", 1)
        except ValueError as err:
            raise orjson.JSONDecodeError("Not enough segments") from err

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error) as err:
            raise orjson.JSONDecodeError("Invalid header padding") from err

        try:
            header = orjson.loads(header_data)
        except ValueError as e:
            raise orjson.JSONDecodeError(f"Invalid header string: {e}") from e

        if not isinstance(header, dict):
            raise orjson.JSONDecodeError("Invalid header string: must be a json object")

        try:
            payload = base64url_decode(payload_segment)
        except (TypeError, binascii.Error) as err:
            raise orjson.JSONDecodeError("Invalid payload padding") from err

        try:
            signature = base64url_decode(crypto_segment)
        except (TypeError, binascii.Error) as err:
            raise orjson.JSONDecodeError("Invalid crypto padding") from err

        return payload, signing_input, header, signature

    def _verify_signature(
            self, signing_input: bytes, header: dict, signature: bytes, key: str = "",
            algorithms: Optional[List[str]] = None,
    ) -> None:
        alg = header.get("alg")
        if not alg or (algorithms is not None and alg not in algorithms):
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        try:
            alg_obj = self.get_algorithm_by_name(alg)
        except NotImplementedError as e:
            raise InvalidAlgorithmError("Algorithm not supported") from e
        key = alg_obj.prepare_key(key)

        if not alg_obj.verify(signing_input, key, signature):
            raise InvalidSignatureError("Signature verification failed")

    def decode_complete(
            self, jwt: str, key: str = "", algorithms: Optional[List[str]] = None,
            options: Optional[Dict[str, Any]] = None, detached_payload: Optional[bytes] = None, **kwargs,
    ) -> Dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
            )
        if options is None:
            options = {}
        merged_options = {**self.options, **options}
        verify_signature = merged_options["verify_signature"]

        if verify_signature and not algorithms:
            raise orjson.JSONDecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        payload, signing_input, header, signature = self._load(jwt)

        if header.get("b64", True) is False:
            if detached_payload is None:
                raise orjson.JSONDecodeError(
                    'It is required that you pass in a value for the "detached_payload" '
                    'argument to decode a message having the b64 header set to false.'
                )
            payload = detached_payload
            signing_input = b".".join([signing_input.rsplit(b".", 1)[0], payload])

        if verify_signature:
            self._verify_signature(signing_input, header, signature, key, algorithms)

        return {
            "payload": payload,
            "header": header,
            "signature": signature,
        }

    def decode(
            self, jwt: str, key: str = "", algorithms: Optional[List[str]] = None,
            options: Optional[Dict[str, Any]] = None, detached_payload: Optional[bytes] = None, **kwargs,
    ) -> str:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
            )
        decoded = self.decode_complete(
            jwt, key, algorithms, options, detached_payload=detached_payload
        )
        return decoded["payload"]
