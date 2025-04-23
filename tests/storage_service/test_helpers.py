import pytest
from django.core.exceptions import ImproperlyConfigured

from archivematica.storage_service.common import helpers


@pytest.mark.parametrize(
    "environment_variable,expected",
    [("YES", True), ("foo", False)],
    ids=["env_var_is_true", "env_var_is_not_true"],
)
def test_is_true(environment_variable: str, expected: bool) -> None:
    assert helpers.is_true(environment_variable) is expected


def test_get_env_variable_fails_when_variable_is_not_set() -> None:
    var_name = "FOO"
    with pytest.raises(
        ImproperlyConfigured, match=f"Set the {var_name} environment variable"
    ):
        helpers.get_env_variable(var_name)


def test_get_env_variable_returns_variable_value_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    var_name = "FOO"
    var_value = "bar"
    monkeypatch.setenv(var_name, var_value)

    assert helpers.get_env_variable(var_name) == var_value


def test_get_oidc_secondary_providers_ignores_provider_if_client_id_and_secret_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDC_RP_CLIENT_ID_FOO", "foo-client-id")
    monkeypatch.setenv("OIDC_RP_CLIENT_SECRET_FOO", "foo-client-secret")
    monkeypatch.setenv("OIDC_RP_CLIENT_ID_BAR", "bar-client-id")
    monkeypatch.setenv("OIDC_RP_CLIENT_SECRET_BAZ", "foo-secret")

    assert helpers.get_oidc_secondary_providers(
        ["FOO", "BAR", "BAZ"], {"given_name": "first_name", "family_name": "last_name"}
    ) == {
        "FOO": {
            "OIDC_OP_AUTHORIZATION_ENDPOINT": "",
            "OIDC_OP_JWKS_ENDPOINT": "",
            "OIDC_OP_LOGOUT_ENDPOINT": "",
            "OIDC_OP_TOKEN_ENDPOINT": "",
            "OIDC_OP_USER_ENDPOINT": "",
            "OIDC_OP_SET_ROLES_FROM_CLAIMS": False,
            "OIDC_OP_ROLE_CLAIM_PATH": "realm_access.roles",
            "OIDC_ACCESS_ATTRIBUTE_MAP": {
                "given_name": "first_name",
                "family_name": "last_name",
            },
            "OIDC_RP_CLIENT_ID": "foo-client-id",
            "OIDC_RP_CLIENT_SECRET": "foo-client-secret",
        }
    }


def test_get_oidc_secondary_providers_strips_provider_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDC_RP_CLIENT_ID_FOO", "foo-client-id")
    monkeypatch.setenv("OIDC_RP_CLIENT_SECRET_FOO", "foo-client-secret")
    monkeypatch.setenv("OIDC_RP_CLIENT_ID_BAR", "bar-client-id")
    monkeypatch.setenv("OIDC_RP_CLIENT_SECRET_BAR", "bar-client-secret")

    assert helpers.get_oidc_secondary_providers(
        ["  FOO", " BAR  "], {"given_name": "first_name", "family_name": "last_name"}
    ) == {
        "FOO": {
            "OIDC_OP_AUTHORIZATION_ENDPOINT": "",
            "OIDC_OP_JWKS_ENDPOINT": "",
            "OIDC_OP_LOGOUT_ENDPOINT": "",
            "OIDC_OP_TOKEN_ENDPOINT": "",
            "OIDC_OP_USER_ENDPOINT": "",
            "OIDC_OP_SET_ROLES_FROM_CLAIMS": False,
            "OIDC_OP_ROLE_CLAIM_PATH": "realm_access.roles",
            "OIDC_ACCESS_ATTRIBUTE_MAP": {
                "given_name": "first_name",
                "family_name": "last_name",
            },
            "OIDC_RP_CLIENT_ID": "foo-client-id",
            "OIDC_RP_CLIENT_SECRET": "foo-client-secret",
        },
        "BAR": {
            "OIDC_OP_AUTHORIZATION_ENDPOINT": "",
            "OIDC_OP_JWKS_ENDPOINT": "",
            "OIDC_OP_LOGOUT_ENDPOINT": "",
            "OIDC_OP_TOKEN_ENDPOINT": "",
            "OIDC_OP_USER_ENDPOINT": "",
            "OIDC_OP_SET_ROLES_FROM_CLAIMS": False,
            "OIDC_OP_ROLE_CLAIM_PATH": "realm_access.roles",
            "OIDC_ACCESS_ATTRIBUTE_MAP": {
                "given_name": "first_name",
                "family_name": "last_name",
            },
            "OIDC_RP_CLIENT_ID": "bar-client-id",
            "OIDC_RP_CLIENT_SECRET": "bar-client-secret",
        },
    }


def test_get_oidc_secondary_providers_capitalizes_provider_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDC_RP_CLIENT_ID_FOO", "foo-client-id")
    monkeypatch.setenv("OIDC_RP_CLIENT_SECRET_FOO", "foo-client-secret")
    monkeypatch.setenv("OIDC_RP_CLIENT_ID_BAR", "bar-client-id")
    monkeypatch.setenv("OIDC_RP_CLIENT_SECRET_BAR", "bar-client-secret")

    assert helpers.get_oidc_secondary_providers(
        ["fOo", "bar"], {"given_name": "first_name", "family_name": "last_name"}
    ) == {
        "FOO": {
            "OIDC_OP_AUTHORIZATION_ENDPOINT": "",
            "OIDC_OP_JWKS_ENDPOINT": "",
            "OIDC_OP_LOGOUT_ENDPOINT": "",
            "OIDC_OP_TOKEN_ENDPOINT": "",
            "OIDC_OP_USER_ENDPOINT": "",
            "OIDC_OP_SET_ROLES_FROM_CLAIMS": False,
            "OIDC_OP_ROLE_CLAIM_PATH": "realm_access.roles",
            "OIDC_ACCESS_ATTRIBUTE_MAP": {
                "given_name": "first_name",
                "family_name": "last_name",
            },
            "OIDC_RP_CLIENT_ID": "foo-client-id",
            "OIDC_RP_CLIENT_SECRET": "foo-client-secret",
        },
        "BAR": {
            "OIDC_OP_AUTHORIZATION_ENDPOINT": "",
            "OIDC_OP_JWKS_ENDPOINT": "",
            "OIDC_OP_LOGOUT_ENDPOINT": "",
            "OIDC_OP_TOKEN_ENDPOINT": "",
            "OIDC_OP_USER_ENDPOINT": "",
            "OIDC_OP_SET_ROLES_FROM_CLAIMS": False,
            "OIDC_OP_ROLE_CLAIM_PATH": "realm_access.roles",
            "OIDC_ACCESS_ATTRIBUTE_MAP": {
                "given_name": "first_name",
                "family_name": "last_name",
            },
            "OIDC_RP_CLIENT_ID": "bar-client-id",
            "OIDC_RP_CLIENT_SECRET": "bar-client-secret",
        },
    }
