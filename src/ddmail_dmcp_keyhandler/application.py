import os
import time
import subprocess
import logging
import ddmail_validators.validators as validators
from flask import Blueprint, current_app, request, make_response, Response
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

bp = Blueprint("application", __name__, url_prefix="/")

@bp.route("/create_key", methods=["POST"])
def create_key() -> Response:
    """
    Create a new encryption key for a user's mailbox.

    This function validates the provided email, key password, and admin password.
    If valid, it generates a new encryption key using the doveadm command.

    Returns:
        Response: Flask response with appropriate message and status code

    Request Form Parameters:
        email (str): The email address of the user
        key_password (str): Base64 encoded password to encrypt the key
        password (str): Admin password to authenticate the request

    Error Responses:
        "error: email is none": If email parameter is missing
        "error: key_password is none": If key_password parameter is missing
        "error: password is none": If password parameter is missing
        "error: email validation failed": If email fails validation
        "error: key_password validation failed": If key_password fails validation
        "error: password validation failed": If password fails validation
        "error: wrong password": If admin password is incorrect
        "error: doveadm binary location is wrong": If doveadm binary doesn't exist
        "error: returncode of cmd doveadm is non zero": If doveadm command fails
        "error: unkown exception running subprocess": If an unexpected error occurs

    Success Response:
        "done": Operation completed successfully
    """
    
    if request.method != 'POST':
        return make_response("Method not allowed", 405)

    ph = PasswordHasher()

    email = request.form.get('email')
    key_password = request.form.get('key_password')
    password = request.form.get('password')

    # Check if input from form is None.
    if email is None:
        current_app.logger.error("email is None")
        return make_response("error: email is none", 200)

    if key_password is None:
        current_app.logger.error("key_password is None")
        return make_response("error: key_password is none", 200)

    if password is None:
        current_app.logger.error("password is None")
        return make_response("error: password is none", 200)

    # Validate email.
    if validators.is_email_allowed(email) != True:
        current_app.logger.error("email validation failed")
        return make_response("error: email validation failed", 200)

    # Validate keypassword, base64 encoded.
    if validators.is_base64_allowed(key_password) != True:
        current_app.logger.error("key_password validation failed")
        return make_response("error: key_password validation failed", 200)

    # Validate password.
    if validators.is_password_allowed(password) != True:
        current_app.logger.error("password validation failed")
        return make_response("error: password validation failed", 200)

    # Check if password is correct.
    try:
        if not ph.verify(current_app.config["PASSWORD_HASH"], password):
            time.sleep(1)
            current_app.logger.error("wrong password")
            return make_response("error: wrong password", 200)
    except VerifyMismatchError:
        time.sleep(1)
        current_app.logger.error("exceptions VerifyMismatchError, wrong password")
        return make_response("error: wrong password", 200)
    time.sleep(1)

    doveadm = current_app.config["DOVEADM_BIN"]

    # Check that doveadm exist.
    if os.path.exists(doveadm) != True:
        current_app.logger.error("doveadm binary location is wrong")
        return make_response("error: doveadm binary location is wrong", 200)

    # Create key with password
    try:
        output = subprocess.run(["/usr/bin/doas",doveadm,"-o","plugin/mail_crypt_private_password="+key_password,"mailbox","cryptokey","generate","-u",email,"-U"], check=True)
        if output.returncode != 0:
            current_app.logger.error("returncode of cmd doveadm is non zero")
            return make_response("error: returncode of cmd doveadm is non zero", 200)
    except subprocess.CalledProcessError as e:
        current_app.logger.error("returncode of cmd doveadm is non zero")
        return make_response("error: returncode of cmd doveadm is non zero", 200)
    except:
        current_app.logger.error("unkown exception running subprocess")
        return make_response("error: unkown exception running subprocess", 200)

    current_app.logger.debug("create key for email " + email + " is done")
    return make_response("done", 200)

@bp.route("/change_password_on_key", methods=["POST"])
def change_password_on_key() -> Response:
    """
    Change the password on an existing encryption key for a user's mailbox.

    This function validates the provided email, current key password, new key password,
    and admin password. If valid, it changes the encryption key password using the doveadm command.

    Returns:
        str: "done" on success
             or an error message describing the issue encountered.

    Request Form Parameters:
        email (str): The email address of the user
        current_key_password (str): Base64 encoded current password of the key
        new_key_password (str): Base64 encoded new password for the key
        password (str): Admin password to authenticate the request

    Error Responses:
        "error: email is none": If email parameter is missing
        "error: current_key_password is none": If current_key_password parameter is missing
        "error: new_key_password is none": If new_key_password parameter is missing
        "error: password is none": If password parameter is missing
        "error: email validation failed": If email fails validation
        "error: current_key_password validation failed": If current_key_password fails validation
        "error: new_key_password validation failed": If new_key_password fails validation
        "error: password validation failed": If password fails validation
        "error: wrong password": If admin password is incorrect
        "error: doveadm binary location is wrong": If doveadm binary doesn't exist
        "error: returncode of cmd doveadm is non zero": If doveadm command fails
        "error: unkown exception running subprocess": If an unexpected error occurs

    Success Response:
        "done": Operation completed successfully
    """
    if request.method != 'POST':
        return make_response("Method not allowed", 405)

    ph = PasswordHasher()

    email = request.form.get('email')
    current_key_password = request.form.get('current_key_password')
    new_key_password = request.form.get('new_key_password')
    password = request.form.get('password')

    # Check if input from form is None.
    if email is None:
        current_app.logger.error("email is None")
        return make_response("error: email is none", 200)

    if current_key_password is None:
        current_app.logger.error("current_key_password is None")
        return make_response("error: current_key_password is none", 200)

    if new_key_password is None:
        current_app.logger.error("new_key_password is None")
        return make_response("error: new_key_password is none", 200)

    if password is None:
        current_app.logger.error("password is None")
        return make_response("error: password is none", 200)

    # Validate email.
    if validators.is_email_allowed(email) != True:
        current_app.logger.error("email validation failed")
        return make_response("error: email validation failed", 200)

    # Validate current_key_password, base64 encoded.
    if validators.is_base64_allowed(current_key_password) != True:
        current_app.logger.error("current_key_password validation failed")
        return make_response("error: current_key_password validation failed", 200)

    # Validate new_key_password, base64 encoded.
    if validators.is_base64_allowed(new_key_password) != True:
        current_app.logger.error("new_key_password validation failed")
        return make_response("error: new_key_password validation failed", 200)

    # Validate password.
    if validators.is_password_allowed(password) != True:
        current_app.logger.error("password validation failed")
        return make_response("error: password validation failed", 200)

    # Check if password is correct.
    try:
        if not ph.verify(current_app.config["PASSWORD_HASH"], password):
            time.sleep(1)
            current_app.logger.error("wrong password")
            return make_response("error: wrong password", 200)
    except:
        time.sleep(1)
        current_app.logger.error("wrong password")
        return make_response("error: wrong password", 200)
    time.sleep(1)

    doveadm = current_app.config["DOVEADM_BIN"]

    # Check that doveadm exist.
    if os.path.exists(doveadm) != True:
        current_app.logger.error("doveadm binary location is wrong")
        return make_response("error: doveadm binary location is wrong", 200)

    # Change password on key.
    try:
        output = subprocess.run(["/usr/bin/doas",doveadm,"mailbox","cryptokey","password","-u",email,"-n",new_key_password,"-o",current_key_password], check=True)
        if output.returncode != 0:
            current_app.logger.error("returncode of cmd doveadm is non zero")
            return make_response("error: returncode of cmd doveadm is non zero", 200)
    except subprocess.CalledProcessError as e:
        current_app.logger.error("returncode of cmd doveadm is non zero")
        return make_response("error: returncode of cmd doveadm is non zero", 200)
    except:
        current_app.logger.error("unkown exception running subprocess")
        return make_response("error: unkonwn exception running subprocess", 200)

    current_app.logger.debug("change password on key for email " + email + " is done")
    return make_response("done", 200)
