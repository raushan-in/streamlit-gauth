# streamlit_gauth/gauth.py
"""
This module provides Google OAuth authentication functionality for Streamlit applications.

The `Authenticate` class handles the OAuth flow, including login, logout, and cookie management.
It uses the `CookieHandler` class internally to manage authentication cookies.

Example:
    ```python
    from streamlit_gauth import Authenticate

    auth = Authenticate()
    auth.check_authentification()
    auth.login()
    ```
"""

import os
import time
from typing import Any, Dict, Literal, Optional

import google_auth_oauthlib.flow
import streamlit as st
from dotenv import load_dotenv
from googleapiclient.discovery import build

from ._cookie import CookieHandler

# Load environment variables from .env file
load_dotenv()

# Constants
GOOGLE_OAUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
]
GOOGLE_LOGO_URL = "https://lh3.googleusercontent.com/COxitqgJr1sJnIDe8-jiKhxDx1FrYbtRHKJ9z_hELisAlapwE9LUPh6fcXIfb5vwpbMl4xl9H9TRFPc5NOO8Sb3VSgIBrfRYvW6cUA"
DEFAULT_LOGIN_BUTTON_NAME = "Sign in with Google"


class Authenticate:
    """
    A class to handle Google OAuth authentication using Streamlit.

    This class manages the OAuth flow, including generating the authorization URL,
    handling the OAuth callback, and managing user sessions via cookies.

    Attributes:
        client_id (str): The Google OAuth client ID.
        client_secret (str): The Google OAuth client secret.
        redirect_uri (str): The redirect URI for Google OAuth.
        cookie_name (str): The name of the cookie used for authentication.
        cookie_key (str): The key used to encrypt/decrypt the cookie.
        cookie_expiry_days (float): The number of days before the cookie expires.
        cookie_handler (CookieHandler): An instance of `CookieHandler` for managing cookies.
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        cookie_name: Optional[str] = None,
        cookie_key: Optional[str] = None,
        cookie_expiry_days: Optional[float] = None,
    ):
        """
        Initialize the Authenticate class.

        Args:
            client_id (Optional[str]): Google OAuth client ID. If not provided, it will be loaded from .env.
            client_secret (Optional[str]): Google OAuth client secret. If not provided, it will be loaded from .env.
            redirect_uri (Optional[str]): Redirect URI for Google OAuth. If not provided, it will be loaded from .env.
            cookie_name (Optional[str]): Name of the cookie to store user info. If not provided, it will be loaded from .env.
            cookie_key (Optional[str]): Key to encrypt/decrypt the cookie. If not provided, it will be loaded from .env.
            cookie_expiry_days (Optional[float]): Expiry time for the cookie in days. If not provided, it will be loaded from .env.
        """
        st.session_state["connected"] = st.session_state.get("connected", False)

        # Load Google OAuth credentials from positional arguments or environment variables
        self.client_id = client_id or os.getenv("GOOGLE_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("GOOGLE_CLIENT_SECRET")

        if not all([self.client_id, self.client_secret]):
            raise ValueError(
                "Google OAuth credentials (client_id, client_secret) must be provided either as arguments or in the .env file."
            )

        # Load redirect URI from positional argument or environment variable
        self.redirect_uri = redirect_uri or os.getenv("GOOGLE_REDIRECT_URI")
        if not self.redirect_uri:
            raise ValueError(
                "Redirect URI must be provided either as an argument or in the .env file as GOOGLE_REDIRECT_URI."
            )

        # Load cookie settings from positional arguments or environment variables
        self.cookie_name = cookie_name or os.getenv("COOKIE_NAME", "google_auth")
        self.cookie_key = cookie_key or os.getenv("COOKIE_KEY")
        self.cookie_expiry_days = float(
            cookie_expiry_days or os.getenv("COOKIE_EXPIRY_DAYS", 30.0)
        )

        if not self.cookie_key:
            raise ValueError(
                "Cookie key must be provided either as an argument or in the .env file as COOKIE_KEY."
            )

        # Initialize cookie handler
        self.cookie_handler = CookieHandler(
            self.cookie_name, self.cookie_key, self.cookie_expiry_days
        )

    def get_authorization_url(self) -> str:
        """
        Generate the Google OAuth authorization URL.

        Returns:
            str: The authorization URL.
        """
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [self.redirect_uri],
                }
            },
            scopes=GOOGLE_OAUTH_SCOPES,
            redirect_uri=self.redirect_uri,
        )
        authorization_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
        )
        return authorization_url

    def login(
        self,
        color: Literal["white", "blue"] = "blue",
        justify_content: str = "center",
        sidebar: bool = False,
        custom_login_button_name: Optional[str] = None,
    ) -> None:
        """
        Render the Google login button.

        Args:
            color (Literal["white", "blue"]): Button color. Defaults to "blue".
            justify_content (str): CSS justify-content value. Defaults to "center".
            sidebar (bool): Whether to render the button in the sidebar. Defaults to False.
            custom_login_button_name (Optional[str]): Custom text for the login button. Defaults to "Sign in with Google".
        """
        if not st.session_state["connected"]:
            authorization_url = self.get_authorization_url()
            login_button_name = custom_login_button_name or DEFAULT_LOGIN_BUTTON_NAME
            html_content = f"""
<div style="display: flex; justify-content: {justify_content};">
    <a href="{authorization_url}" target="_self" style="background-color: {'#fff' if color == 'white' else '#4285f4'}; color: {'#000' if color == 'white' else '#fff'}; text-decoration: none; text-align: center; font-size: 16px; margin: 4px 2px; cursor: pointer; padding: 8px 12px; border-radius: 4px; display: flex; align-items: center;">
        <img src="{GOOGLE_LOGO_URL}" alt="Google logo" style="margin-right: 8px; width: 26px; height: 26px; background-color: white; border: 2px solid white; border-radius: 4px;">
        {login_button_name}
    </a>
</div>
"""
            if sidebar:
                st.sidebar.markdown(html_content, unsafe_allow_html=True)
            else:
                st.markdown(html_content, unsafe_allow_html=True)

    def check_authentification(self) -> None:
        """
        Check if the user is authenticated and handle the OAuth flow.

        This method checks for an existing authentication cookie and handles the OAuth callback
        if the user is redirected back from Google OAuth.
        """
        if not st.session_state["connected"]:
            token = self.cookie_handler.get_cookie()
            if token:
                self._set_session_state_from_token(token)
                return

            time.sleep(0.3)

            if not st.session_state["connected"]:
                auth_code = st.query_params.get("code")
                st.query_params.clear()
                if auth_code:
                    self._handle_oauth_callback(auth_code)

    def _set_session_state_from_token(self, token: Dict[str, Any]) -> None:
        """
        Set the session state from a token.

        Args:
            token (Dict[str, Any]): Token containing user info.
        """
        user_info = {
            "name": token["name"],
            "email": token["email"],
            "picture": token["picture"],
            "id": token["oauth_id"],
        }
        st.session_state["connected"] = True
        st.session_state["user_info"] = user_info
        st.session_state["oauth_id"] = user_info["id"]

    def _handle_oauth_callback(self, auth_code: str) -> None:
        """
        Handle the OAuth callback and fetch user info.

        Args:
            auth_code (str): The authorization code from Google OAuth.
        """
        try:
            flow = google_auth_oauthlib.flow.Flow.from_client_config(
                client_config={
                    "web": {
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [self.redirect_uri],
                    }
                },
                scopes=GOOGLE_OAUTH_SCOPES,
                redirect_uri=self.redirect_uri,
            )
            flow.fetch_token(code=auth_code)
            credentials = flow.credentials
            user_info_service = build(
                serviceName="oauth2",
                version="v2",
                credentials=credentials,
            )
            user_info = user_info_service.userinfo().get().execute()

            st.session_state["connected"] = True
            st.session_state["oauth_id"] = user_info.get("id")
            st.session_state["user_info"] = user_info
            self.cookie_handler.set_cookie(
                user_info.get("name"),
                user_info.get("email"),
                user_info.get("picture"),
                user_info.get("id"),
            )
            st.rerun()
        except Exception as e:
            st.error(f"An error occurred during authentication: {e}")

    def logout(self) -> None:
        """
        Log out the user by clearing the session state and deleting the cookie.
        """
        st.session_state["logout"] = True
        st.session_state["name"] = None
        st.session_state["username"] = None
        st.session_state["connected"] = None
        self.cookie_handler.delete_cookie()
