#!/usr/bin/env python3
"""Simple Flask app with user authentication features.
"""
import logging

from flask import Flask, abort, jsonify, redirect, request

from auth import Auth

logging.disable(logging.WARNING)


AUTH = Auth()
app = Flask(__name__)


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """GET
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """POST /users
    """
    # Get  email and password from form data
    email, password = request.form.get("email"), request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """POST /sessions
    """
    # Get user credentials from form data
    email, password = request.form.get("email"), request.form.get("password")
    if not AUTH.valid_login(email, password):
        abort(401)
    # Create  new session for the user
    session_id = AUTH.create_session(email)
    # Construct response with a JSON payload
    response = jsonify({"email": email, "message": "logged in"})
    # Set cookie with the session ID on the response
    response.set_cookie("session_id", session_id)
    # Return the response
    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    """DELETE /sessions
    """
    # Get session ID from the "session_id" cookie in the request
    session_id = request.cookies.get("session_id")
    # Retrieve user associated with the session ID
    user = AUTH.get_user_from_session_id(session_id)
    # If no user is found, abort request with a 403 Forbidden error
    if user is None:
        abort(403)
    # Destroy session associated with the user
    AUTH.destroy_session(user.id)
    # Redirect to home route
    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    """GET /profile
    """
    # Get session ID from the "session_id" cookie in the request
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    # If no user is found, abort  request with a 403 Forbidden error
    if user is None:
        abort(403)
    # Return  user's email as a JSON payload
    return jsonify({"email": user.email})


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> str:
    """POST /reset_password
    """
    # Retrieve email from the form data
    email = request.form.get("email")
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "reset_token": reset_token})


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password() -> str:
    """PUT /reset_password
    """
    # Retrieve  email, reset_token and new_password from the form data
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        # If  reset token is invalid, return an HTTP 403 error
        abort(403)
    return jsonify({"email": email, "message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
