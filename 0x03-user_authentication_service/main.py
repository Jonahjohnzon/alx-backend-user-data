#!/usr/bin/env python3
"""Module for simple end-to-end integration test for `app.py`.
"""

import requests

from app import AUTH

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://0.0.0.0:5000"


def register_user(email: str, password: str) -> None:
    """Test registration of a user.
    """
    url = "{}/users".format(BASE_URL)
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}
    response = requests.post(url, data=data)
    assert response.status_code == 400
    assert response.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Test logging with wrong password.
    """
    url = "{}/sessions".format(BASE_URL)
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=data)
    assert response.status_code == 401


def profile_unlogged() -> None:
    """Tests behavior of trying to retrieve profile
    while being logged out.
    """
    url = "{}/profile".format(BASE_URL)
    response = requests.get(url)
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Test retrieving profile information whilst logged in.
    """
    url = "{}/profile".format(BASE_URL)
    cookies = {
        "session_id": session_id
    }
    response = requests.get(url, cookies=cookies)
    assert response.status_code == 200
    payload = response.json()
    assert "email" in payload
    user = AUTH.get_user_from_session_id(session_id)
    assert user.email == payload["email"]


def log_out(session_id: str) -> None:
    """Tests tests the process of logging out from a session.
    """
    # Make a request to log out  user
    url = "{}/sessions".format(BASE_URL)
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "session_id": session_id
    }
    response = requests.delete(url, headers=headers, cookies=data)
    assert response.status_code == 200


def reset_password_token(email: str) -> str:
    """Tests the process of requesting password reset.
    """
    # Make POST request to the "/reset_password" endpoint
    url = "{}/reset_password".format(BASE_URL)
    data = {
        "email": email
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert "email" in response.json()
    assert response.json()["email"] == email
    reset_token = response.json()["reset_token"]
    # Return  reset_token
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Tests updating  user's password.
    """
    url = "{}/reset_password".format(BASE_URL)
    data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put(url, data=data)
    # Assert the status code of  response is 200
    assert response.status_code == 200
    # Assert the message in response matches the expected message
    assert response.json()["message"] == "Password updated"
    # Assert the email in response matches the email passed in
    assert response.json()["email"] == email


def log_in(email: str, password: str) -> str:
    """Tests logging in.
    """
    url = "{}/sessions".format(BASE_URL)
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=data)
    if response.status_code == 401:
        return "Invalid credentials"
    assert response.status_code == 200
    response_json = response.json()
    assert "email" in response_json
    assert "message" in response_json
    assert response_json["email"] == email
    # Return session ID from the response cookie
    return response.cookies.get("session_id")


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
