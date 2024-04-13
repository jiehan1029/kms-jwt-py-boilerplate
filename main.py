"""
Use AWS KMS to sign and verify JWT.
Call create_jwt() to create a KMS-signed JWT.
Call decode_jwt(encoded) to use KMS verify signature and then decode.
"""
import base64
import binascii
import json
import os
import jwt
import boto3
from botocore.client import BaseClient
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import serialization as crypto_serialization
from dotenv import load_dotenv

load_dotenv()

DEFAULT_KMS_KEY_ARN = os.environ.get("KMS_KEY_ARN")
DEFAULT_KMS_REGION = os.environ.get("KMS_REGION")
default_kms_client = None


def set_up_default_kms_client(region_name: str = DEFAULT_KMS_REGION, **kwargs) -> BaseClient:
    global default_kms_client
    if default_kms_client:
        return default_kms_client
    if not region_name:
        raise ValueError("Missing KMS region name!")
    # if your env doesn't have aws profile configured in the env, pass aws access key id and secret to kwargs
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html#boto3.session.Session
    default_kms_client = boto3.client("kms", region_name=region_name, **kwargs)
    return default_kms_client


def kms_sign_message(message: bytes,
                     signing_algorithm: str = "ECDSA_SHA_256",
                     kms_client: BaseClient = set_up_default_kms_client(),
                     kms_key_id: str = DEFAULT_KMS_KEY_ARN,
                     dry_run: bool = False) -> None | bytes:
    if not kms_client:
        raise ValueError("Invalid kms_client!")
    if not kms_key_id:
        raise ValueError("Invalid kms_key_id!")
    response = kms_client.sign(
        KeyId=kms_key_id, Message=message, MessageType="RAW", SigningAlgorithm=signing_algorithm, DryRun=dry_run
    )
    return response["Signature"]


def kms_verify_signature(
        message: bytes, signature: bytes,
        signing_algorithm: str = "ECDSA_SHA_256",
        kms_client: BaseClient = set_up_default_kms_client(),
        kms_key_id: str = DEFAULT_KMS_KEY_ARN,
        dry_run: bool = False) -> bool:
    if not kms_client:
        raise ValueError("Invalid kms_client!")
    if not kms_key_id:
        raise ValueError("Invalid kms_key_id!")
    response = kms_client.verify(
        KeyId=kms_key_id,
        Message=message,
        MessageType="RAW",
        Signature=signature,
        SigningAlgorithm=signing_algorithm,
        DryRun=dry_run,
    )
    return response["SignatureValid"]


def kms_get_public_key(kms_client: BaseClient = set_up_default_kms_client(), kms_key_id: str = DEFAULT_KMS_KEY_ARN) -> bytes:
    """
    The value from KMS response is a DER-encoded X.509 public key, also known as SubjectPublicKeyInfo (SPKI), as defined in RFC 5280.
    This method converts the DER-encoded X.509 public key to perm key, for example
    b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESgoyhsxkPXUVLuqsJ3DHtqjy0Wyo\nVR4jZNMtLokFWP9g1UOdhEfsNoEYPvHe5ikpok6/bV7b0E64dDGpJU3O4Q==\n-----END PUBLIC KEY-----\n'  # noqa
    """
    if not kms_client:
        raise ValueError("Invalid kms_client!")
    if not kms_key_id:
        raise ValueError("Invalid kms_key_id!")
    response = kms_client.get_public_key(KeyId=kms_key_id)
    # create ECPublicKey obj, an instance of rsa.RSAPublicKey
    public_key_obj = crypto_serialization.load_der_public_key(response["PublicKey"])
    # serialize the RSAPublicKey to bytes given encoding and format
    pub_key_bytes = public_key_obj.public_bytes(
        encoding=crypto_serialization.Encoding.PEM, format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pub_key_bytes


def encode_urlsafe_base64(payload: dict | bytes, strip_padding: bool = True) -> str:
    """
    strip_padding=True is necessary for JWT signature.
    """
    if isinstance(payload, dict):
        encoded_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    else:
        encoded_str = base64.urlsafe_b64encode(payload).decode()
    if strip_padding:
        encoded_str = encoded_str.rstrip("=")
    return encoded_str


def decode_urlsafe_base64(bytes_payload: bytes, restore_padding: bool = True) -> bytes:
    """
    restore_padding=True is necessary when decode JWT signature for KMS verification.
    """
    decoded_bytes = bytes_payload
    if restore_padding:
        missing_padding = len(bytes_payload.decode()) % 4
        if missing_padding:
            decoded_bytes += b"=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(decoded_bytes)


def bytes_to_number(string):
    return int(binascii.b2a_hex(string), 16)


def number_to_bytes(num, num_bytes):
    padded_hex = "%0*x" % (2 * num_bytes, num)
    big_endian = binascii.a2b_hex(padded_hex.encode("ascii"))
    return big_endian


# reference: https://github.com/blockstack-packages/jsontokens-py/blob/master/jsontokens
def raw_to_der_signature(raw_sig: bytes, num_bits: int = 256) -> bytes:
    """convert RS formatted signature from JWT back to DER encoded to use in KMS.verify()"""
    num_bytes = (num_bits + 7) // 8
    if len(raw_sig) != 2 * num_bytes:
        raise ValueError("Invalid signature")
    r = bytes_to_number(raw_sig[:num_bytes])
    s = bytes_to_number(raw_sig[num_bytes:])
    return encode_dss_signature(r, s)


def der_to_raw_signature(der_sig, num_bits: int = 256) -> bytes:
    """convert DER formatted signature from KMS.sign() to R||S format that is used in JWT signature"""
    num_bytes = (num_bits + 7) // 8
    r, s = decode_dss_signature(der_sig)
    return number_to_bytes(r, num_bytes) + number_to_bytes(s, num_bytes)


def create_jwt(jwt_payload: dict,
               jwt_alg: str = "ES256",
               kms_key_id: str = DEFAULT_KMS_KEY_ARN,
               kms_client: BaseClient = set_up_default_kms_client()) -> str:
    """
    :param jwt_alg: must match signing algorithm used in KMS sign
    :param jwt_payload: example
    {
        "aud": ["your-audience"],
        "iss": "the-issuer",
        "sub": "the-subject",
        "iat": datetime.now().timestamp(),
        "nbf": datetime.now().timestamp(),
        "exp": (datetime.now() + timedelta(minutes=5)).timestamp(),
    }
    :param kms_key_id: KMS key id or full ARN
    :param kms_client: KMS client
    :return: KMS key signed JWT
    """
    if not kms_key_id:
        raise ValueError("Missing kms_key_id!")

    jwt_header = {"alg": jwt_alg, "typ": "JWT", "kid": kms_key_id}
    message = f"{encode_urlsafe_base64(jwt_header)}.{encode_urlsafe_base64(jwt_payload)}"
    # NOTE: use signing_algorithm compatible with JWT alg for KMS sign
    signature = kms_sign_message(message=message.encode(),
                                 signing_algorithm="ECDSA_SHA_256",
                                 kms_client=kms_client,
                                 kms_key_id=kms_key_id)
    if not signature:
        raise Exception("Failed to sign the message")
    # NOTE: convert DER formatted signature from kms_client.sign() to RS formatted for JWT
    sig_str = encode_urlsafe_base64(der_to_raw_signature(signature))
    return f"{message}.{sig_str}"


def decode_jwt(jwt_encoded: str,
               jwt_aud: str | None = None,
               kms_verify: bool = True,
               kms_client: BaseClient = set_up_default_kms_client(),
               kms_key_id: str = DEFAULT_KMS_KEY_ARN) -> dict:
    """
    Verify and then decode a KMS signed JWT.
    :param jwt_encoded: the encoded JWT
    :param jwt_aud: the audience of the JWT, valid value is one of the "aud" element in JWT header.
        - https://github.com/jpadilla/pyjwt/blob/master/docs/usage.rst#audience-claim-aud
    :param kms_verify: when True, only use KMS verify() method and skip pyjwt signature validation
    :param kms_client: must be valid either from arg or env default
    :param kms_key_id: must be valid either from arg or env default
    """
    jwt_parts = jwt_encoded.split(".")
    jwt_header = json.loads(decode_urlsafe_base64(jwt_parts[0].encode()).decode())
    jwt_alg = jwt_header.get("alg")
    if not jwt_alg:
        raise ValueError(f"Missing alg in JWT header!")
    # message should be the same message bytes used in sign_message
    message = ".".join(jwt_parts[0:2]).encode()
    # signature should be the generated one from sign_message, Base64-encoded binary data object
    signature = raw_to_der_signature(decode_urlsafe_base64(jwt_parts[2].encode()))
    if kms_verify:
        # NOTE: update signing_algorithm to the one compatible with jwt_alg for KMS sign
        # here assume jwt_alg = "ES256" which corresponds to "ECDSA_SHA_256" in KMS
        signature_valid = kms_verify_signature(message=message,
                                               signing_algorithm="ECDSA_SHA_256",
                                               signature=signature,
                                               kms_client=kms_client,
                                               kms_key_id=kms_key_id)
        if not signature_valid:
            raise Exception(f"Failed to validate JWT signature!")
        # for convenience, skip JWT signature verification after verified by KMS
        decoded_header = jwt.get_unverified_header(jwt_encoded)
        decoded_payload = jwt.decode(jwt_encoded, options={"verify_signature": False})
        return {"header": decoded_header, "payload": decoded_payload, "signature": jwt_parts[2]}

    # this works too (more pyjwt-style), get the public key from KMS and use pyjwt to verify signature
    public_key = kms_get_public_key(kms_client=kms_client, kms_key_id=kms_key_id)
    if not public_key:
        raise ValueError("Invalid public key!")
    if jwt_aud:
        decoded_jwt = jwt.decode(jwt=jwt_encoded, audience=jwt_aud, key=public_key, algorithms=[jwt_alg])
    else:
        decoded_jwt = jwt.decode(jwt=jwt_encoded, key=public_key, algorithms=[jwt_alg])
    return decoded_jwt

