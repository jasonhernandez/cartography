from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cartography.intel.aws.kms import get_aliases
from cartography.intel.aws.kms import get_grants
from cartography.intel.aws.kms import get_policy
from cartography.intel.aws.kms import transform_kms_key_policies
from tests.data.aws.kms import ACCESS_DENIED_KMS_KEY_DETAILS


def test_transform_kms_key_policies_with_null_policy():
    """Test that KMS key policies with None values result in null policy analysis properties."""
    # Arrange
    policy_alias_grants_data = ACCESS_DENIED_KMS_KEY_DETAILS

    # Act - Should gracefully handle keys with None policy (AccessDenied)
    result = transform_kms_key_policies(policy_alias_grants_data)

    # Assert - Keys with None policy should have null policy analysis properties
    assert len(result) == 2

    # First key
    key1_data = result["9a1ad414-6e3b-47ce-8366-6b8f26ba467d"]
    assert key1_data["kms_key"] == "9a1ad414-6e3b-47ce-8366-6b8f26ba467d"
    assert key1_data["anonymous_access"] is None
    assert key1_data["anonymous_actions"] is None

    # Second key
    key2_data = result["1b2cd345-7e8f-49ab-cdef-0123456789ab"]
    assert key2_data["kms_key"] == "1b2cd345-7e8f-49ab-cdef-0123456789ab"
    assert key2_data["anonymous_access"] is None
    assert key2_data["anonymous_actions"] is None


@pytest.mark.parametrize(
    "error_code,should_raise",
    [
        ("NotFoundException", False),
        ("AccessDeniedException", False),
        ("ThrottlingException", True),
    ],
)
def test_get_policy_skips_deleted_key(error_code, should_raise):
    """A key deleted between ListKeys and GetKeyPolicy must not fail the sync."""
    client = MagicMock()
    client.get_key_policy.side_effect = ClientError(
        {"Error": {"Code": error_code, "Message": "x"}}, "GetKeyPolicy"
    )
    key = {"KeyId": "9a1ad414-6e3b-47ce-8366-6b8f26ba467d"}

    if should_raise:
        with pytest.raises(ClientError):
            get_policy(key, client)
    else:
        assert get_policy(key, client) is None


@pytest.mark.parametrize(
    "error_code,should_raise",
    [
        ("NotFoundException", False),
        ("AccessDeniedException", False),
        ("ThrottlingException", True),
    ],
)
def test_get_aliases_skips_deleted_key(error_code, should_raise):
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = ClientError(
        {"Error": {"Code": error_code, "Message": "x"}}, "ListAliases"
    )
    key = {"KeyId": "9a1ad414-6e3b-47ce-8366-6b8f26ba467d"}

    if should_raise:
        with pytest.raises(ClientError):
            get_aliases(key, client)
    else:
        assert get_aliases(key, client) == []


@pytest.mark.parametrize(
    "error_code,should_raise",
    [
        ("NotFoundException", False),
        ("AccessDeniedException", False),
        ("ThrottlingException", True),
    ],
)
def test_get_grants_skips_deleted_key(error_code, should_raise):
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = ClientError(
        {"Error": {"Code": error_code, "Message": "x"}}, "ListGrants"
    )
    key = {"KeyId": "9a1ad414-6e3b-47ce-8366-6b8f26ba467d"}

    if should_raise:
        with pytest.raises(ClientError):
            get_grants(key, client)
    else:
        assert get_grants(key, client) == []
