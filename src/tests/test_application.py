from flask import current_app
import pytest
import os

def test_hash_data(client):
    response_hash_data_post = client.post("/hash_data", data={"data":"password"})
    assert response_hash_data_post.status_code == 200
    assert b"argon2id" in response_hash_data_post.data

def test_hash_data_illigal_char(client):
    response_hash_data_post = client.post("/hash_data", data={"data":"-password"})
    assert response_hash_data_post.status_code == 200
    assert b"error: validation of data failed" in response_hash_data_post.data

def test_create_key_illigal_char_password(client):
    response_hash_data_post = client.post("/create_key", data={"password":".password","key_password":"password","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: password validation failed" in response_hash_data_post.data

def test_create_key_illigal_char_key_password(client):
    response_hash_data_post = client.post("/create_key", data={"password":"password","key_password":"p<assword","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: key_password validation failed" in response_hash_data_post.data

def test_create_key_illigal_char_email(client):
    response_hash_data_post = client.post("/create_key", data={"password":"password","key_password":"password","email":"te\"st@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: email validation failed" in response_hash_data_post.data

def test_create_key_wrong_password(client):
    response_hash_data_post = client.post("/create_key", data={"password":"wrongpassword","key_password":"password","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: wrong password" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_password(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":".password","current_key_password":"password","new_key_password":"password","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_current_key_password(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"password","current_key_password":"p<assword","new_key_password":"password","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: current_key_password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_new_key_password(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"password","current_key_password":"password","new_key_password":"pas%sword","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: new_key_password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_email(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"password","current_key_password":"password","new_key_password":"password","email":"test@te--st.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: email validation failed" in response_hash_data_post.data

def test_change_password_on_key_wrong_password(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"wrongpassword","current_key_password":"password","new_key_password":"password","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: wrong password" in response_hash_data_post.data
