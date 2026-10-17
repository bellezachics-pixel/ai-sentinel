"""Tests de autenticacion: registro, login, lockout, refresh, logout."""
import pytest

from conftest import AUTH_PREFIX, make_user


def test_register_validation_errors(client):
    # Username demasiado corto (min 3)
    resp = client.post(
        f"{AUTH_PREFIX}/register",
        json={"username": "ab", "email": "ab@example.com", "password": "Passw0rd!x"},
    )
    assert resp.status_code == 422

    # Password sin mayuscula / numero / especial
    resp = client.post(
        f"{AUTH_PREFIX}/register",
        json={"username": "validuser", "email": "v@example.com", "password": "password"},
    )
    assert resp.status_code == 422

    # Username con caracteres no permitidos
    resp = client.post(
        f"{AUTH_PREFIX}/register",
        json={"username": "bad user!", "email": "b@example.com", "password": "Passw0rd!x"},
    )
    assert resp.status_code == 422


def test_register_success_returns_tokens(client):
    user = make_user(client)
    assert user["access"]
    assert user["refresh"]


def test_login_wrong_password_returns_401(client):
    make_user(client, username="logintest1")
    resp = client.post(
        f"{AUTH_PREFIX}/login",
        json={"username": "logintest1", "password": "WrongPass1!"},
    )
    assert resp.status_code == 401


def test_bruteforce_lockout_after_repeated_failures(client):
    from app.core.security import rate_limit_store

    make_user(client, username="lockme1")
    # Umbral real del codigo: 5 intentos fallidos -> bloqueo de 15 min.
    # El contador del middleware de rate limit es por IP (compartido entre
    # paths), asi que limpiamos solo el contador de requests para poder
    # llegar al umbral de fuerza bruta de la ruta.
    for _ in range(5):
        rate_limit_store.requests.clear()
        resp = client.post(
            f"{AUTH_PREFIX}/login",
            json={"username": "lockme1", "password": "WrongPass1!"},
        )
        assert resp.status_code == 401

    # Sexto intento: la ruta detecta >= 5 fallos y bloquea la IP -> 429
    rate_limit_store.requests.clear()
    resp = client.post(
        f"{AUTH_PREFIX}/login",
        json={"username": "lockme1", "password": "WrongPass1!"},
    )
    assert resp.status_code == 429


def test_me_with_access_token(client):
    user = make_user(client)
    resp = client.get(f"{AUTH_PREFIX}/me", headers=user["headers"])
    assert resp.status_code == 200
    assert resp.json()["username"] == user["username"]


def test_refresh_flow_issues_usable_access_token(client):
    user = make_user(client)
    resp = client.post(
        f"{AUTH_PREFIX}/refresh", json={"refresh_token": user["refresh"]}
    )
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert new_tokens["access_token"]

    resp = client.get(
        f"{AUTH_PREFIX}/me",
        headers={"Authorization": f"Bearer {new_tokens['access_token']}"},
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == user["username"]


def test_refresh_token_rejected_as_access_token(client):
    user = make_user(client)
    resp = client.get(
        f"{AUTH_PREFIX}/me",
        headers={"Authorization": f"Bearer {user['refresh']}"},
    )
    assert resp.status_code == 401


def test_logout_revokes_access_token(client):
    user = make_user(client)
    resp = client.post(f"{AUTH_PREFIX}/logout", headers=user["headers"])
    assert resp.status_code == 200

    resp = client.get(f"{AUTH_PREFIX}/me", headers=user["headers"])
    assert resp.status_code == 401
