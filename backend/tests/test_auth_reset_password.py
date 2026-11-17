"""
Tests for the /api/auth/reset-password endpoint (CWE-287 remediation).
Password resets must require authentication and be limited to the account
owner or an admin.
"""
from models import User, db


URL = '/api/auth/reset-password'


def test_reset_password_requires_authentication(client, sample_user):
    """Unauthenticated callers must not be able to change any password"""
    response = client.post(URL, json={
        'email': sample_user.email,
        'new_password': 'attacker-password'
    })
    assert response.status_code == 401
    assert User.query.get(sample_user.id).check_password('password123')


def test_reset_password_rejects_invalid_token(client, sample_user):
    """A forged/invalid token is treated as unauthenticated"""
    response = client.post(
        URL,
        json={'email': sample_user.email, 'new_password': 'attacker-password'},
        headers={'Authorization': 'Bearer not-a-valid-token'}
    )
    assert response.status_code == 401
    assert User.query.get(sample_user.id).check_password('password123')


def test_reset_password_own_account(client, sample_user, auth_headers):
    """An authenticated user can reset their own password"""
    response = client.post(
        URL,
        json={'email': sample_user.email, 'new_password': 'new-password-1'},
        headers=auth_headers
    )
    assert response.status_code == 200
    assert User.query.get(sample_user.id).check_password('new-password-1')


def test_reset_password_other_user_forbidden(client, sample_user, admin_user, auth_headers):
    """A regular user cannot reset another user's password"""
    response = client.post(
        URL,
        json={'email': admin_user.email, 'new_password': 'attacker-password'},
        headers=auth_headers
    )
    assert response.status_code == 403
    assert User.query.get(admin_user.id).check_password('admin123')


def test_reset_password_unknown_email_forbidden(client, auth_headers):
    """Unknown emails get the same response as foreign accounts"""
    response = client.post(
        URL,
        json={'email': 'nobody@example.com', 'new_password': 'x-password'},
        headers=auth_headers
    )
    assert response.status_code == 403


def test_reset_password_admin_can_reset_other_user(client, sample_user, admin_auth_headers):
    """Admins may reset other users' passwords"""
    response = client.post(
        URL,
        json={'email': sample_user.email, 'new_password': 'admin-set-pw'},
        headers=admin_auth_headers
    )
    assert response.status_code == 200
    assert User.query.get(sample_user.id).check_password('admin-set-pw')


def test_reset_password_missing_fields(client, auth_headers):
    """Missing fields yield a 400 for authenticated callers"""
    response = client.post(URL, json={'email': 'test@example.com'}, headers=auth_headers)
    assert response.status_code == 400
