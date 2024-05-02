from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user

# Test authorizing the user admin login
@pytest.mark.asyncio
async def test_authorize_user_admin_login(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Login and get the access token
    token_response = await async_client.post("/login", headers=headers)
    assert token_response.status_code == 307

# Test listing users as an ADMIN or a MANAGER after inputing an invalid Skip Integer value
@pytest.mark.asyncio
async def test_listing_users_as_admin_or_manager_after_inputing_invalid_skip_integer_value(async_client, admin_token):
    url = "/users/"
    parameters = {"skip": -1}
    headers = {"Authorization": f"Bearer {admin_token}"}

    response = await async_client.get(url=url, params=parameters, headers=headers)

    assert response.status_code == 500
    assert response.json()["detail"] == "The Skip Integer value -1 cannot be less than 0"

# Test listing users as an ADMIN or a MANAGER after inputing an invalid Limit Integer value
@pytest.mark.asyncio
async def test_listing_users_as_admin_or_manager_after_inputing_invalid_limit_integer_value(async_client, admin_token):
    url = "/users/"
    parameters = {"limit": 0}
    headers = {"Authorization": f"Bearer {admin_token}"}

    response = await async_client.get(url=url, params=parameters, headers=headers)

    assert response.status_code == 500
    assert response.json()["detail"] == "The Limit Integer value 0 cannot be less than 1"

# Fixtures for common test data
@pytest.fixture
def user_data():
    return {
        "email": "john.doe@example.com",
        "nickname": "john_doe123",
        "first_name": "John",
        "last_name": "Doe",
        "bio": "Experienced software developer specializing in web applications.",
        "profile_picture_url": "https://example.com/profiles/john.jpg",
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe"
    }

# Test a user to update their own profile information
@pytest.mark.asyncio
async def test_update_own_user_profile_information(async_client, verified_user, user_data):
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234",
        "role": UserRole.AUTHENTICATED
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})

    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    response_token = data["access_token"]
    headers = {"Authorization": f"Bearer {response_token}"}
    response = await async_client.put("/update-own-user-profile/", json=user_data, headers=headers)

    assert response.status_code == 200
    assert response.json()["email"] == user_data["email"]
    assert response.json()["nickname"] == user_data["nickname"]
    assert response.json()["first_name"] == user_data["first_name"]
    assert response.json()["last_name"] == user_data["last_name"]
    assert response.json()["bio"] == user_data["bio"]
    assert response.json()["profile_picture_url"] == user_data["profile_picture_url"]
    assert response.json()["linkedin_profile_url"] == user_data["linkedin_profile_url"]
    assert response.json()["github_profile_url"] == user_data["github_profile_url"]

# Test a user to update their own profile information when the user does not exist
@pytest.mark.asyncio
async def test_update_own_user_profile_information_when_the_user_does_not_exist(async_client, user_token, user_data):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put("/update-own-user-profile/", json=user_data, headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

# Test a user to update their own profile information with a duplicate email
@pytest.mark.asyncio
async def test_update_own_user_profile_information_with_a_duplicate_email(async_client, db_session, verified_user, user_data):
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234",
        "role": UserRole.AUTHENTICATED
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})

    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    user_data["hashed_password"] = "Secure*1234"
    user_data["role"] = UserRole.AUTHENTICATED

    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()

    updated_user_data = {
        "email": "john.doe@example.com",
    }

    response_token = data["access_token"]
    headers = {"Authorization": f"Bearer {response_token}"}
    response = await async_client.put("/update-own-user-profile/", json=updated_user_data, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already exists"

# Test a user to update their own profile information with a duplicate nickname
@pytest.mark.asyncio
async def test_update_own_user_profile_information_with_a_duplicate_nickname(async_client, db_session, verified_user, user_data):
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234",
        "role": UserRole.AUTHENTICATED
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})

    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    user_data["hashed_password"] = "Secure*1234"
    user_data["role"] = UserRole.AUTHENTICATED

    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()

    updated_user_data = {
        "nickname": "john_doe123",
    }

    response_token = data["access_token"]
    headers = {"Authorization": f"Bearer {response_token}"}
    response = await async_client.put("/update-own-user-profile/", json=updated_user_data, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "Nickname already exists"

# Fixtures for common test data
@pytest.fixture
def user_notified():
    return {
        "id": "12345678-1234-1234-1234-123456789abc",
        "email": "john.doe@example.com",
        "nickname": "john_doe123",
        "hashed_password": "Secure*1234",
        "first_name": "John",
        "last_name": "Doe",
        "bio": "Experienced software developer specializing in web applications.",
        "profile_picture_url": "https://example.com/profiles/john.jpg",
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe",
        "role": UserRole.AUTHENTICATED,
        "is_professional": False
    }

# Test setting a user's professional status when the user does not exist
@pytest.mark.asyncio
async def test_setting_a_user_professional_status_when_the_user_does_not_exist(async_client, admin_token, user_notified):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.post("/login", headers=headers)
    assert response.status_code == 307

    url = f"/users/{user_notified["id"]}/set-professional-status/{user_notified["is_professional"]}"
    json = {"is_professional": user_notified["is_professional"]}
    response = await async_client.put(url=url, json=json, headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

from unittest.mock import patch

# Test setting a user's professional status to true as an administrator
@pytest.mark.asyncio
async def test_updating_a_user_professional_status_to_true_as_an_admin(async_client, db_session, admin_token, user_notified):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.post("/login", headers=headers)
    assert response.status_code == 307

    with patch("app.services.email_service.EmailService.send_updated_professional_status_email") as test_send_email:
        test_send_email.return_value = None
        user_notified["is_professional"] = True

        user = User(**user_notified)
        db_session.add(user)
        await db_session.commit()

        url = f"/users/{user_notified["id"]}/set-professional-status/{user_notified["is_professional"]}"
        json = {"is_professional": user_notified["is_professional"]}
        response = await async_client.put(url=url, json=json, headers=headers)
        assert response.status_code == 200
        assert response.json()["is_professional"] == True

# Test setting a user's professional status to false as an administrator
@pytest.mark.asyncio
async def test_updating_a_user_professional_status_to_false_as_an_admin(async_client, db_session, admin_token, user_notified):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.post("/login", headers=headers)
    assert response.status_code == 307

    with patch("app.services.email_service.EmailService.send_updated_professional_status_email") as test_send_email:
        test_send_email.return_value = None
        user_notified["is_professional"] = False

        user = User(**user_notified)
        db_session.add(user)
        await db_session.commit()

        url = f"/users/{user_notified["id"]}/set-professional-status/{user_notified["is_professional"]}"
        json = {"is_professional": user_notified["is_professional"]}
        response = await async_client.put(url=url, json=json, headers=headers)
        assert response.status_code == 200
        assert response.json()["is_professional"] == False
