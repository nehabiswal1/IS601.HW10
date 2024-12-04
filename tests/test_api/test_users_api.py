from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

# Fixture to generate a user token
@pytest.fixture
async def user_token(async_client, verified_user):
    """
    Generate a JWT token for a verified user.
    """
    login_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"  # Replace with the actual password of verified_user
    }
    response = await async_client.post("/login/", data=urlencode(login_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 200
    return response.json()["access_token"]

# Fixture to generate an admin token
@pytest.fixture
async def admin_token(async_client, admin_user):
    """
    Generate a JWT token for an admin user.
    """
    login_data = {
        "username": admin_user.email,
        "password": "AdminPassword123!"  # Replace with the actual password of admin_user
    }
    response = await async_client.post("/login/", data=urlencode(login_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 200
    return response.json()["access_token"]

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

# Other test functions remain unchanged...
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

# Additional test functions here remain unchanged...

