"""
Handle the creation, retrieval, and deletion of cookies for password-less re-authentication.
"""

from datetime import datetime, timedelta

import extra_streamlit_components as stx
import jwt
import streamlit as st
from jwt import DecodeError, InvalidSignatureError


class CookieHandler:
    """
    A class to handle the creation, retrieval, and deletion of cookies for password-less re-authentication.

    This class is used internally by the `Authenticate` class and is not part of the public API.
    Users should not interact with this class directly.

    Attributes:
        cookie_name (str): The name of the cookie stored on the client's browser.
        cookie_key (str): The key used to hash the signature of the re-authentication cookie.
        cookie_expiry_days (float): The number of days before the cookie expires.
        cookie_manager (stx.CookieManager): The Streamlit cookie manager instance.
        token (str): The JWT token stored in the cookie.
        exp_date (float): The expiration date of the cookie in Unix timestamp format.
    """

    def __init__(
        self, cookie_name: str, cookie_key: str, cookie_expiry_days: float = 30.0
    ):
        """
        Initialize the CookieHandler.

        Args:
            cookie_name (str): The name of the cookie stored on the client's browser.
            cookie_key (str): The key used to hash the signature of the re-authentication cookie.
            cookie_expiry_days (float): The number of days before the cookie expires. Defaults to 30.0.
        """
        self.cookie_name = cookie_name
        self.cookie_key = cookie_key
        self.cookie_expiry_days = cookie_expiry_days
        self.cookie_manager = stx.CookieManager()
        self.token = None
        self.exp_date = None

    def get_cookie(self) -> str:
        """
        Retrieve and decode the re-authentication cookie.

        Returns:
            str: The decoded JWT token if the cookie is valid and not expired, otherwise False.
        """
        if "logout" in st.session_state and st.session_state["logout"]:
            return False
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self._token_decode()
            if (
                self.token is not False
                and "email" in self.token.keys()
                and self.token["exp_date"] > datetime.now().timestamp()
            ):
                return self.token

    def delete_cookie(self):
        """
        Delete the re-authentication cookie from the client's browser.
        """
        try:
            self.cookie_manager.delete(self.cookie_name)
        except KeyError as e:
            print(e)

    def set_cookie(self, name: str, email: str, picture: str, oauth_id: str):
        """
        Set the re-authentication cookie on the client's browser.

        Args:
            name (str): The user's name.
            email (str): The user's email.
            picture (str): The URL of the user's profile picture.
            oauth_id (str): The user's OAuth ID.
        """
        self.exp_date = self._set_exp_date()
        token = self._token_encode(name, email, picture, oauth_id)
        self.cookie_manager.set(
            self.cookie_name,
            token,
            expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days),
        )

    def _set_exp_date(self) -> str:
        """
        Set the expiration date for the re-authentication cookie.

        Returns:
            str: The expiration date in Unix timestamp format.
        """
        return (datetime.now() + timedelta(days=self.cookie_expiry_days)).timestamp()

    def _token_decode(self) -> str:
        """
        Decode the JWT token stored in the cookie.

        Returns:
            str: The decoded JWT token if valid, otherwise False.
        """
        try:
            return jwt.decode(self.token, self.cookie_key, algorithms=["HS256"])
        except InvalidSignatureError as e:
            print(e)
            return False
        except DecodeError as e:
            print(e)
            return False

    def _token_encode(self, name: str, email: str, picture: str, oauth_id: str) -> str:
        """
        Encode user information into a JWT token.

        Args:
            name (str): The user's name.
            email (str): The user's email.
            picture (str): The URL of the user's profile picture.
            oauth_id (str): The user's OAuth ID.

        Returns:
            str: The encoded JWT token.
        """
        return jwt.encode(
            {
                "email": email,
                "name": name,
                "picture": picture,
                "oauth_id": oauth_id,
                "exp_date": self.exp_date,
            },
            self.cookie_key,
            algorithm="HS256",
        )
