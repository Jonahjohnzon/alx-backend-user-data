#!/usr/bin/env python3
"""
Module for authentication
"""
import os
from typing import List, TypeVar

from flask import request


class Auth():
    """Template for authentication system implemented in this app.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """This function takes path and a list of excluded paths as arguments
        and returns a boolean value.
        """
        # If path is None, return True
        if not path:
            return True
        # If excluded_paths  None or empty, return True
        if not excluded_paths:
            return True
        # Remove the trailing slash from the path
        path = path.rstrip("/")
        # Check if path is in excluded_paths and return False if path is
        for excluded_path in excluded_paths:
            # Check if given path starts with excluded path, with * at the end
            if excluded_path.endswith("*") and \
                    path.startswith(excluded_path[:-1]):
                # Return False if path starts with excluded path with * at end
                return False
            # Check if the given path is equal to the excluded path
            elif path == excluded_path.rstrip("/"):
                # Return False if the path is equal to the excluded path
                return False
        # If path is not in excluded_paths, return True
        return True

    def authorization_header(self, request=None) -> str:
        """Gets the value of the Authorization header from the request
        """
        # If request is None, return None
        # If request doesn’t contain the header key Authorization, return None
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """This function takes request object as an optional argument
        (defaults to None) and returns a value of type 'User'.
        """
        return None

    def session_cookie(self, request=None) -> str:
        """Retrieves the session cookie from a request.
        """
        # If request is not None
        if request is not None:
            # Get the name of the session cookie from SESSION_NAME env variable
            cookie_name = os.getenv('SESSION_NAME')
            # Return the value of the session cookie
            return request.cookies.get(cookie_name)
