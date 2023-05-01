import json
import os
import time
from base64 import urlsafe_b64encode

import jwt
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from dotenv import load_dotenv
from github import Github
from jwt.exceptions import InvalidTokenError
from requests.exceptions import HTTPError

from logging_config import DebugLogger, SecurityLogger

load_dotenv()

# The target user whose repositories and .md files will be searched.
# TODO: remove this (testing only)
TARGET_USERNAME = os.environ.get("TARGET_USERNAME")

# Get the GitHub App ID and the private key path from the environment variables
GH_SKEY_PATH = os.environ.get("GH_APP_PRIVATE_KEY_PATH")
GITHUB_APP_ID = os.environ.get("GH_APP_ID")
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
        InvalidPrivateKeyError: If an invalid PEM-encoded RSA private key is provided.
        InvalidTokenError: If an invalid token is provided.
        ValueError: If there was a problem loading the private key.
    """
    try:
        with open(private_key_path, "rb") as key_file:
            # private_key = jwt.jwk_from_pem(key_file.read())
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key
    except InvalidPrivateKeyError as e:
        logger.error("Invalid private key provided: %s", str(e))
        raise InvalidPrivateKeyError("Failed to load private key.")
    except (InvalidTokenError, InvalidSignature) as e:
        logger.error("Invalid token provided: %s", str(e))
        raise InvalidTokenError("Failed to load private key.")
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


def make_request(private_key, url, method, data=None, headers=None):
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
        signature = sign_request(private_key, request_body)
        headers["Authorization"] = f"Bearer {signature}"
        response = requests.request(method, url, json=data, headers=headers)
        response.raise_for_status()
        return response.json()
    except HTTPError as e:
        logger.error(f"Failed to make request: {e}")
        raise ValueError("Request failed.")
    except Exception as e:
        logger.error(f"Failed to make request: {e}")
        raise ValueError("Request failed.")


def generate_jwt_token(private_key: RSAPrivateKey, app_id: str) -> str:
    """
    Generate a JWT token signed with the provided private key and the GitHub App ID.

    Args:
        private_key (RSAPrivateKey): The RSA private key to use for signing the JWT token.
        app_id (str): The ID of the GitHub App for which the token is being generated.

    Returns:
        str: The JWT token as a string.

    Raises:
        ValueError: If either the private_key or app_id is not provided or is of invalid type.
        InvalidTokenError: If there is an issue with the JWT token.
    """
    # Validate input
    if not private_key or not isinstance(private_key, RSAPrivateKey):
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
        encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

        # return encoded_jwt.decode("utf-8")
        return encoded_jwt
    except InvalidTokenError as e:
        logger.error("Invalid token provided: %s", str(e))
        raise InvalidTokenError("Failed to generate JWT token.")
    except Exception as e:
        logger.error("Failed to generate JWT token: %s", str(e))
        raise ValueError("Failed to generate JWT token.")


if __name__ == "__main__":
    # load the GitHub App's private key from a secure location
    private_key = load_private_key(GH_SKEY_PATH)
    app_id = GITHUB_APP_ID

    jwt_token = generate_jwt_token(private_key, app_id)

    # Authenticate with the GitHub API using the JWT token
    g = Github(jwt_token)

    # Search for the target user's public repos
    user = g.get_user(TARGET_USERNAME)
    repos = user.get_repos()

    try:
        # Loop through the repos and extract the .md files
        for repo in repos:
            contents = repo.get_contents("")
            for content_file in contents:
                if content_file.path.endswith(".md"):
                    # get the raw file contents
                    data = make_request(
                        private_key,
                        content_file.download_url,
                        "GET",
                    )
                    text = data["content"]
                    # log the extracted text
                    logger.info(text)
                    # Do something with the extracted text
    except InvalidPrivateKeyError as e:
        logger.error("Failed to load private key: %s", str(e))
    except InvalidTokenError as e:
        logger.error("Failed to generate JWT token: %s", str(e))
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
