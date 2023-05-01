import json
import os
import time
import traceback
from base64 import urlsafe_b64encode
from typing import Dict, Optional

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv
from jwt import JWT, AbstractJWKBase, jwk_from_pem
from jwt.exceptions import InvalidKeyTypeError, JWTDecodeError, UnsupportedKeyTypeError
from requests.exceptions import HTTPError

from logging_config import DebugLogger, SecurityLogger

load_dotenv()
jwt = JWT()

# The target user whose repositories and .md files will be searched.
# TODO: remove this (testing only)
TARGET_USERNAME = os.environ.get("TARGET_USERNAME")

# Get the GitHub App ID and the private key path from the environment variables
GH_SKEY_PATH = os.environ.get("GH_APP_PRIVATE_KEY_PATH")
GITHUB_APP_ID = os.environ.get("GH_APP_ID")
GH_APP_JWT = os.environ.get("GH_APP_JWT")  # validated
JWT_NEG_BUFFER_TIME = 60  # set iat to 1 minute in the past
JWT_EXPIRATION_TIME = 8 * 60  # 8 minute expiration time

# Validate that the GitHub App ID and private key path are set.
if not GITHUB_APP_ID:
    raise ValueError("GH_APP_ID environment variable is not set.")
if not GH_SKEY_PATH:
    raise ValueError("GH_APP_PRIVATE_KEY_PATH environment variable is not set.")

# Get the loggers
# Default logger: info and above to a rotating file; not propagated to root logger
logger = SecurityLogger
# Debug logger: debug and above to only the console; not propagated to root logger
debug_logger = DebugLogger


# Custom error classes for load_private_key and sign_request
class InvalidPrivateKeyError(Exception):
    pass


class InvalidTokenError(Exception):
    pass


def load_private_key(private_key_path):
    """
    Loads an RSA private key from the provided file path and returns it as a cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey object.

    Args:
        private_key_path (str): Path to the file containing the private key.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: RSA private key object loaded from the file.

    Raises:
        InvalidKeyTypeError: If an invalid PEM-encoded RSA private key is provided.
        UnsupportedKeyTypeError: If a key is provided in an unsupported format.
        ValueError: If there was a problem loading the private key.
    """
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = jwk_from_pem(key_file.read())
            # private_key = serialization.load_pem_private_key(
            #     key_file.read(),
            #     password=None,
            # )
        return private_key
    except InvalidKeyTypeError as e:
        logger.error("Invalid private key provided: %s", str(e))
        raise InvalidPrivateKeyError("Failed to load private key.")
    except (UnsupportedKeyTypeError, InvalidSignature) as e:
        logger.error("Unsupported private key provided: %s", str(e))
        raise InvalidPrivateKeyError("Failed to load private key.")
    except Exception as e:
        logger.error("Failed to load private key from %s: %s", private_key_path, str(e))
        raise ValueError("Failed to load private key.")


def sign_request(private_key, request_body):
    """
    Signs the given request body using the provided private key and returns the resulting signature as a URL-safe Base64-encoded string.

    Args:
        private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): Private key to use for signing the request.
        request_body (str): Request body to sign.

    Returns:
        str: Hex-encoded signature resulting from signing the request body.

    Raises:
        InvalidSignature: If the resulting signature is invalid.
        ValueError: If there is an error generating the signature.
    """
    try:
        signature = private_key.sign(
            request_body.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        signature = urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
        return signature
    except (InvalidTokenError, InvalidSignature) as e:
        logger.error("Failed to sign request: %s", str(e))
        raise InvalidSignature("Failed to sign request.")
    except Exception as e:
        logger.error("Failed to sign request: %s", str(e))
        raise ValueError("Failed to sign request.")


def make_request(jwt_token, url, method, data=None, headers=None):
    """
    Sends an HTTP request with the provided private key and returns the response as a JSON object.

    Args:
        private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): Private key to use for signing the request.
        url (str): URL of the endpoint to make the request to.
        method (str): HTTP method of the request to send.
        data (dict): Data to include in the request body.
        headers (dict): Additional headers to include in the request.

    Returns:
        dict: JSON response from the API endpoint.

    Raises:
        HTTPError (requests.exceptions): If there is an error with the HTTP request.
        ValueError: If the request fails or the response status code is not 200.
    """
    headers = headers or {}
    request_body = "" if not data else json.dumps(data, separators=(",", ":"))
    try:
        # signature = sign_request(private_key, request_body)
        headers["Authorization"] = f"Bearer {jwt_token}"
        response = requests.request(method, url, json=request_body, headers=headers)
        response.raise_for_status()
        return response.json()
    except HTTPError as e:
        logger.error(f"Failed to make request: {e}")
        raise ValueError("Request failed.")
    except Exception as e:
        logger.error(f"Failed to make request: {e}")
        raise ValueError("Request failed.")


def generate_jwt_token(private_key: AbstractJWKBase, app_id: str) -> str:
    """
    Generate a JWT token signed with the provided private key and the GitHub App ID.

    Args:
        private_key (AbstractJWKBase): The RSA private key to use for signing the JWT token.
            Underneath, it is cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey (https://github.com/GehirnInc/python-jwt/blob/068db420c9ae957925daf0f5a2baa9319ac20c82/jwt/jwk.py#L346)
        app_id (str): The ID of the GitHub App for which the token is being generated.

    Returns:
        str: The JWT token as a string.

    Raises:
        ValueError: If either the private_key or app_id is not provided or is of invalid type.
        InvalidTokenError: If there is an issue with the JWT token.
    """
    # Validate input
    if not private_key or not isinstance(private_key, AbstractJWKBase):
        raise ValueError("Invalid private key provided.")
    if not app_id or not isinstance(app_id, str):
        raise ValueError("Invalid app ID provided.")

    try:
        # Get the current time in Unix time
        now = int(time.time())

        # set the payload for the JWT token
        payload = {
            "iat": now - JWT_NEG_BUFFER_TIME,
            "exp": now + JWT_EXPIRATION_TIME,
            "iss": app_id,
        }

        # sign the payload with the GitHub App's private key
        encoded_jwt = jwt.encode(payload, private_key, alg="RS256")

        # return encoded_jwt.decode("utf-8")
        return encoded_jwt
    except InvalidTokenError as e:
        logger.error("Invalid token provided: %s", str(e))
        raise InvalidTokenError("Failed to generate JWT token.")
    except Exception as e:
        logger.error("Failed to generate JWT token: %s", str(e))
        raise ValueError("Failed to generate JWT token.")


def validate_jwt_token(
    jwt_token: str, private_key: AbstractJWKBase, app_id: str
) -> bool:
    """
    Validate a JWT token signed with the provided private key and the GitHub App ID.

    Args:
        jwt_token (str): The JWT token to validate.
        private_key (RSAPrivateKey): The RSA private key to use for validating the JWT token.
        app_id (str): The ID of the GitHub App for which the token is being validated.

    Returns:
        bool: True if the JWT token is valid, False otherwise.

    Raises:
        ValueError: If either the jwt_token, private_key, or app_id is not provided or is of invalid type.
        InvalidTokenError: If there is an issue with the JWT token.
        JWTDecodeError: If there is an issue decoding the JWT token.
    """
    # Validate input
    if not jwt_token or not isinstance(jwt_token, str):
        raise ValueError("Invalid JWT token provided.")
    if not private_key or not isinstance(private_key, AbstractJWKBase):
        raise ValueError("Invalid private key provided.")
    if not app_id or not isinstance(app_id, str):
        raise ValueError("Invalid app ID provided.")

    try:
        # Decode the JWT token
        decoded_jwt = jwt.decode(jwt_token, private_key, algorithms=["RS256"])

        # Check that the decoded JWT token contains the expected claims
        if not decoded_jwt["iss"] == app_id:
            raise InvalidTokenError("Invalid token provided.")
        if not decoded_jwt["iat"] <= int(time.time()) <= decoded_jwt["exp"]:
            raise InvalidTokenError("Invalid token provided.")

        return True
    except (InvalidTokenError, JWTDecodeError) as e:
        # TODO: find a better way to handle this
        # This is a special case where the token is expired, we want to return false and let the flow generate a new token
        # Ref: https://github.com/GehirnInc/python-jwt/blob/068db420c9ae957925daf0f5a2baa9319ac20c82/jwt/jwt.py#L107
        if str(e) == "JWT Expired":
            logger.info(
                "Invalid token provided, return false and let the flow generate new token: %s",
                str(e),
            )
            return False
        logger.error(
            "Failed to validate JWT token (InvalidTokenError or JWTDecodeError outside of expected behaviour): %s",
            str(e),
        )
        raise InvalidTokenError("Failed to validate JWT token.")

    except Exception as e:
        logger.error("Failed to validate JWT token: %s", str(e))
        raise ValueError("Failed to validate JWT token.")


def make_request(
    jwt_token: str,
    method: str,
    url: str,
    request_body: Optional[Dict] = None,
    headers: Optional[Dict] = None,
) -> Dict:
    """
    Sends a HTTP request with the specified method and URL, and returns the response as a JSON dictionary.

    Args:
        jwt_token (str): A JWT token string for authenticating the request.
        method (str): The HTTP method to use for the request (e.g. GET, POST, etc.).
        url (str): The URL to send the request to.
        request_body (Optional[Dict]): A dictionary containing the request body data to send (if applicable).
        headers (Optional[Dict]): A dictionary containing additional headers to send with the request (if applicable).

    Returns:
        A dictionary containing the JSON response from the server.

    Raises:
        ValueError: If the request fails for any reason, including HTTP errors or exceptions.

    Examples:
        >>> jwt_token = "some_jwt_token"
        >>> method = "GET"
        >>> url = "https://api.github.com/users/someuser/repos"
        >>> headers = {"User-Agent": "my-app"}
        >>> response = make_request(jwt_token, method, url, headers=headers)
    """

    try:
        if method not in ["GET", "POST", "PUT", "DELETE"]:
            raise ValueError(f"Invalid method: {method}")

        response = requests.request(
            method=method,
            url=url,
            # ONLY if headers is not None, spread it and add the Authorization header
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"{jwt_token}",
                "X-GitHub-Api-Version": "2022-11-28",
                **(headers if headers is not None else {}),
            },
            json=request_body,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error occurred: {e}")
        raise ValueError("Request failed.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception occurred: {e}")
        raise ValueError("Request failed.")


if __name__ == "__main__":
    # load the GitHub App's private key from a secure location
    private_key = load_private_key(GH_SKEY_PATH)
    app_id = GITHUB_APP_ID
    jwt_token = GH_APP_JWT

    # Generate a JWT token if one is not provided or if the provided one is invalid
    if not jwt_token or not validate_jwt_token(jwt_token, private_key, app_id):
        jwt_token = generate_jwt_token(private_key, app_id)
        logger.info("JWT token: %s", jwt_token)

    try:
        gh_url = f"https://api.github.com/users/{TARGET_USERNAME}/repos"
        # Make a request to the GitHub API
        results = make_request(jwt_token=jwt_token, method="GET", url=gh_url)

        # TODO: remove this
        logger.info(results)

    except InvalidPrivateKeyError as e:
        logger.error("Failed to load private key: %s", str(e))
    except InvalidTokenError as e:
        logger.error("Failed to generate JWT token: %s", str(e))
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        traceback.print_exc()
