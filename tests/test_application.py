import pytest
import os
import subprocess
from flask import current_app
from argon2.exceptions import VerifyMismatchError

def test_create_key_illigal_char_password(client):
    """Test creating key with illegal character in admin password
    
    This test verifies that the application properly validates the admin password parameter
    and rejects requests containing illegal characters (specifically a period '.' in this case).
    The password validation should fail and return an appropriate error message.
    """
    response_hash_data_post = client.post("/create_key", data={"password":".password","key_password":"aDfrdf43DFR432dFtrfde43E","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: password validation failed" in response_hash_data_post.data

def test_create_key_illigal_char_key_password(client,password):
    """Test to create key with illegal character in key_password
    
    This test verifies that the application properly validates the key_password parameter
    and rejects requests containing illegal characters in the key_password field.
    """
    response_hash_data_post = client.post("/create_key", data={"password":password,"key_password":"p<assword","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: key_password validation failed" in response_hash_data_post.data

def test_create_key_illigal_char_email(client):
    """Test to create key with illegal character in email
    
    This test verifies that the application properly validates the email parameter
    and rejects requests containing illegal characters in the email field.
    """
    response_hash_data_post = client.post("/create_key", data={"password":"password","key_password":"password","email":"te\"st@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: email validation failed" in response_hash_data_post.data

def test_create_key_wrong_password(client):
    """Test authentication with wrong admin password when changing key password
    
    This test verifies that the application correctly rejects requests with an incorrect
    admin password when attempting to change a key password.
    """
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"adFrd34fd34rFDert4edFTRE","current_key_password":"sd34fgFD34fdERF43edSDFTR","new_key_password":"dDFrdswD34fdSed3fdRtfrtf","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: wrong password" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_password(client):
    """Test changing key password with illegal character in admin password
    
    This test verifies that the application properly validates the admin password parameter
    and rejects requests containing illegal characters when changing a key password.
    """
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"aSdfrGf345fdrtGFrdFR54.2","current_key_password":"sd34fgFD34fdERF43edSDFTR","new_key_password":"dDFrdswD34fdSed3fdRtfrtf","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_current_key_password(client):
    """Test changing key password with illegal character in current key password
    
    This test verifies that the application properly validates the current_key_password parameter
    and rejects requests containing illegal characters when changing a key password.
    """
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"password","current_key_password":"p<assword","new_key_password":"password","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: current_key_password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_new_key_password(client, password):
    """Test changing key password with illegal character in new key password
    
    This test verifies that the application properly validates the new_key_password parameter
    and rejects requests containing illegal characters when changing a key password.
    """
    response_hash_data_post = client.post("/change_password_on_key", data={"password":password,"current_key_password":"aSdf3fde34fDFR345fdeFDRT","new_key_password":"pas%sword","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: new_key_password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_email(client):
    """Test changing key password with illegal character in email
    
    This test verifies that the application properly validates the email parameter
    and rejects requests containing illegal characters when changing a key password.
    """
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"password","current_key_password":"password","new_key_password":"password","email":"test@te--st.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: email validation failed" in response_hash_data_post.data

def test_change_password_on_key_wrong_password(client):
    """Test changing key password with incorrect admin password
    
    This test verifies that the application rejects requests to change a key password
    when an incorrect admin password is provided.
    """
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"A3D4fEf3D3F45gFds23F4gfR","current_key_password":"aDfD3fdFd3rFDs345FdsFrdf","new_key_password":"aDfrGf34fdFgt54fdFgfrdfT","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: wrong password" in response_hash_data_post.data

def test_create_key_missing_email(client):
    """Test creating key with missing email parameter
    
    This test verifies that the application properly checks for the presence of the email parameter
    and rejects requests that don't include it.
    """
    response = client.post("/create_key", data={"password":"validPassword123","key_password":"validBase64Key=="})
    assert response.status_code == 200
    assert b"error: email is none" in response.data

def test_create_key_missing_key_password(client):
    """Test creating key with missing key_password parameter
    
    This test verifies that the application properly checks for the presence of the key_password parameter
    and rejects requests that don't include it.
    """
    response = client.post("/create_key", data={"password":"validPassword123","email":"test@test.se"})
    assert response.status_code == 200
    assert b"error: key_password is none" in response.data

def test_create_key_missing_password(client):
    """Test creating key with missing admin password parameter
    
    This test verifies that the application properly checks for the presence of the password parameter
    and rejects requests that don't include it.
    """
    response = client.post("/create_key", data={"key_password":"validBase64Key==","email":"test@test.se"})
    assert response.status_code == 200
    assert b"error: password is none" in response.data

def test_create_key_invalid_doveadm_path(client, monkeypatch, password):
    """Test creating key with invalid doveadm binary path
    
    This test verifies that the application properly checks if the doveadm binary exists
    at the configured location and returns an appropriate error if it doesn't.
    """
    # Temporarily modify the app config to set an invalid doveadm path
    monkeypatch.setitem(client.application.config, "DOVEADM_BIN", "/nonexistent/path/to/doveadm")

    response = client.post("/create_key", data={
        "password": password,
        "key_password": "validBase64Key==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: doveadm binary location is wrong" in response.data

def test_create_key_subprocess_error(client, monkeypatch, password, mocker):
    """Test creating key when the doveadm subprocess returns an error
    
    This test verifies that the application properly handles subprocess errors
    when executing the doveadm command and returns an appropriate error message.
    """
    # Ensure doveadm path exists for this test
    monkeypatch.setitem(client.application.config, "DOVEADM_BIN", "/bin/ls")

    # Mock subprocess.run to raise CalledProcessError
    mock_run = mocker.patch('subprocess.run')
    mock_run.side_effect = subprocess.CalledProcessError(1, "cmd")

    response = client.post("/create_key", data={
        "password": password,
        "key_password": "validBase64Key==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: returncode of cmd doveadm is non zero" in response.data

def test_create_key_subprocess_unknown_error(client, monkeypatch, password, mocker):
    """Test creating key when the doveadm subprocess raises an unexpected exception
    
    This test verifies that the application properly handles unexpected exceptions
    when executing the doveadm command and returns an appropriate error message.
    """
    # Ensure doveadm path exists for this test
    monkeypatch.setitem(client.application.config, "DOVEADM_BIN", "/bin/ls")

    # Mock subprocess.run to raise a generic exception
    mock_run = mocker.patch('subprocess.run')
    mock_run.side_effect = Exception("Unknown error")

    response = client.post("/create_key", data={
        "password": password,
        "key_password": "validBase64Key==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: unkown exception running subprocess" in response.data

def test_create_key_success(client, monkeypatch, password, mocker):
    """Test successfully creating a key
    
    This test verifies that the application successfully creates a key
    when all parameters are valid and the doveadm command succeeds.
    """
    # Ensure doveadm path exists for this test
    monkeypatch.setitem(client.application.config, "DOVEADM_BIN", "/bin/ls")

    # Mock subprocess.run to return success
    mock_run = mocker.patch('subprocess.run')
    mock_run.return_value.returncode = 0

    response = client.post("/create_key", data={
        "password": password,
        "key_password": "validBase64Key==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"done" in response.data

# Tests for change_password_on_key function

def test_change_password_on_key_missing_email(client):
    """Test changing key password with missing email parameter
    
    This test verifies that the application properly checks for the presence of the email parameter
    and rejects requests that don't include it when changing a key password.
    """
    response = client.post("/change_password_on_key", data={
        "password": "validPassword123",
        "current_key_password": "currentValidBase64==",
        "new_key_password": "newValidBase64=="
    })
    assert response.status_code == 200
    assert b"error: email is none" in response.data

def test_change_password_on_key_missing_current_key_password(client):
    """Test changing key password with missing current_key_password parameter
    
    This test verifies that the application properly checks for the presence of the current_key_password parameter
    and rejects requests that don't include it when changing a key password.
    """
    response = client.post("/change_password_on_key", data={
        "password": "validPassword123",
        "new_key_password": "newValidBase64==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: current_key_password is none" in response.data

def test_change_password_on_key_missing_new_key_password(client):
    """Test changing key password with missing new_key_password parameter
    
    This test verifies that the application properly checks for the presence of the new_key_password parameter
    and rejects requests that don't include it when changing a key password.
    """
    response = client.post("/change_password_on_key", data={
        "password": "validPassword123",
        "current_key_password": "currentValidBase64==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: new_key_password is none" in response.data

def test_change_password_on_key_missing_password(client):
    """Test changing key password with missing admin password parameter
    
    This test verifies that the application properly checks for the presence of the password parameter
    and rejects requests that don't include it when changing a key password.
    """
    response = client.post("/change_password_on_key", data={
        "current_key_password": "currentValidBase64==",
        "new_key_password": "newValidBase64==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: password is none" in response.data

def test_change_password_on_key_invalid_doveadm_path(client, monkeypatch, password):
    """Test changing key password with invalid doveadm binary path
    
    This test verifies that the application properly checks if the doveadm binary exists
    at the configured location and returns an appropriate error if it doesn't when changing a key password.
    """
    # Temporarily modify the app config to set an invalid doveadm path
    monkeypatch.setitem(client.application.config, "DOVEADM_BIN", "/nonexistent/path/to/doveadm")

    response = client.post("/change_password_on_key", data={
        "password": password,
        "current_key_password": "currentValidBase64==",
        "new_key_password": "newValidBase64==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: doveadm binary location is wrong" in response.data

def test_change_password_on_key_subprocess_error(client, monkeypatch, password, mocker):
    """Test changing key password when the doveadm subprocess returns an error
    
    This test verifies that the application properly handles subprocess errors
    when executing the doveadm command to change a key password and returns an appropriate error message.
    """
    # Ensure doveadm path exists for this test
    monkeypatch.setitem(client.application.config, "DOVEADM_BIN", "/bin/ls")

    # Mock subprocess.run to raise CalledProcessError
    mock_run = mocker.patch('subprocess.run')
    mock_run.side_effect = subprocess.CalledProcessError(1, "cmd")

    response = client.post("/change_password_on_key", data={
        "password": password,
        "current_key_password": "currentValidBase64==",
        "new_key_password": "newValidBase64==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: returncode of cmd doveadm is non zero" in response.data

def test_change_password_on_key_subprocess_unknown_error(client, monkeypatch, password, mocker):
    """Test changing key password when the doveadm subprocess raises an unexpected exception
    
    This test verifies that the application properly handles unexpected exceptions
    when executing the doveadm command to change a key password and returns an appropriate error message.
    """
    # Ensure doveadm path exists for this test
    monkeypatch.setitem(client.application.config, "DOVEADM_BIN", "/bin/ls")

    # Mock subprocess.run to raise a generic exception
    mock_run = mocker.patch('subprocess.run')
    mock_run.side_effect = Exception("Unknown error")

    response = client.post("/change_password_on_key", data={
        "password": password,
        "current_key_password": "currentValidBase64==",
        "new_key_password": "newValidBase64==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: unkonwn exception running subprocess" in response.data

def test_change_password_on_key_success(client, monkeypatch, password, mocker):
    """Test successfully changing a key password
    
    This test verifies that the application successfully changes a key password
    when all parameters are valid and the doveadm command succeeds.
    """
    # Ensure doveadm path exists for this test
    monkeypatch.setitem(client.application.config, "DOVEADM_BIN", "/bin/ls")

    # Mock subprocess.run to return success
    mock_run = mocker.patch('subprocess.run')
    mock_run.return_value.returncode = 0

    response = client.post("/change_password_on_key", data={
        "password": password,
        "current_key_password": "currentValidBase64==",
        "new_key_password": "newValidBase64==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"done" in response.data

def test_create_key_password_verify_error(client, monkeypatch, mocker):
    """Test creating key with admin password verification failure
    
    This test verifies that the application properly handles password verification errors
    by mocking the PasswordHasher.verify method to raise a VerifyMismatchError exception.
    The application should return an error indicating the password is wrong.
    """
    # Mock PasswordHasher.verify to raise VerifyMismatchError
    ph_verify_mock = mocker.patch('argon2.PasswordHasher.verify')
    ph_verify_mock.side_effect = VerifyMismatchError()

    response = client.post("/create_key", data={
        "password": "AAAAAAAAAAAAAAAAAAAAAAAA",
        "key_password": "validBase64Key==",
        "email": "test@test.se"
    })
    assert response.status_code == 200
    assert b"error: wrong password" in response.data
