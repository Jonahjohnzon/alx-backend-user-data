#!/usr/bin/env python3
"""Module for authentication.
"""


import logging
from typing import Union
from uuid import uuid4

import bcrypt
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User

logging.disable(logging.WARNING)


def _hash_password(password: str) -> bytes:
    """Hashes password and returns bytes.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generate uuid.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with  authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers new user with given email and password.
        """
        try:
            self._db.find_user_by(email=email)
            # If user already exist with passed email, raise a ValueError
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass
        hashed_password = _hash_password(password)
        user = self._db.add_user(email, hashed_password)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if  user's email and password are valid.
        """
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                password_bytes = password.encode('utf-8')
                hashed_password = user.hashed_password
                if bcrypt.checkpw(password_bytes, hashed_password):
                    return True
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Creates session and returns  session ID as a string.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        # If user None, return None
        if user is None:
            return None
        # Generate new UUID and store it in db as the user’s session_id
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        # Return the session ID.
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieve User object from  session ID.
        """
        # If  session ID is None or no user is found, return None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            # If no user object is found, return None
            return None
        # Otherwise return corresponding user.
        return user

    def destroy_session(self, user_id: int) -> None:
        """Method to destroy session associated with a user
        """
        # If user ID  None, return None
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates password reset token for a user.
        """
        # Find user with the specified email address
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None
        # If no user is found with specified email address, raise a ValueError
        if user is None:
            raise ValueError()
        # Generate a new password reset token & update the user's record in db
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        # Return generated password reset token
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates user's password using a reset token.
        """
        # Find user associated with reset_token
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")
        # Hash the new password
        new_hashed_password = _hash_password(password)
        # Update the user's hashed password and the reset_token field to None
        self._db.update_user(
            user.id,
            hashed_password=new_hashed_password,
            reset_token=None,
        )
