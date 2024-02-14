#!/usr/bin/env python3
""" Module of basic authentication
"""
from flask import request
from typing import List, TypeVar
import base64
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ Class of Basic Authentication
    """

    def __init__(self) -> None:
        """ Class constructure
        """
        super().__init__()

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """ Method that generates and returns a Base64 Authorization
        """
        if not authorization_header:
            return None
        if type(authorization_header) is not str:
            return None
        if not authorization_header.startswith('Basic '):
            return None
        else:
            return authorization_header.split(' ')[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """ Method that decodes the Base64
        """
        if not base64_authorization_header:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            result = base64.decodebytes(
                base64_authorization_header.encode('utf-8')
            )
            return result.decode('utf-8')
        except ValueError:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
            ) -> (str, str):  # type: ignore
        """ Method that return the User email and password
        """
        if not decoded_base64_authorization_header:
            return (None, None)
        if type(decoded_base64_authorization_header) is not str:
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        credent = decoded_base64_authorization_header.split(':', 1)
        if credent:
            return (credent[0], credent[1])
        return (None, None)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str
            ) -> TypeVar('User'):  # type: ignore
        """ Method that returns the User based on its email and password
        """
        if not user_email or not isinstance(user_email, str):
            return None
        if not user_pwd or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({'email': user_email})
            if not users:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
        except KeyError:
            return None
        return None

    def current_user(self, request=None) -> TypeVar('User'):  # type: ignore
        """ Method that overloads the Auth and retrieves the User instance
        """
        try:
            header = self.authorization_header(request)
            extracted_base64 = self.extract_base64_authorization_header(header)
            decoded = self.decode_base64_authorization_header(extracted_base64)
            credentials = self.extract_user_credentials(decoded)
            return self.user_object_from_credentials(
                credentials[0], credentials[1])
        except Exception:
            return None
