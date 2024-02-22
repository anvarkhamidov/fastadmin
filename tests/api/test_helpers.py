import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from fastadmin.api.helpers import is_valid_id, is_valid_int, is_valid_uuid, sanitize_filter_value
from fastadmin.api.service import get_user_id_from_session_id
from fastadmin.settings import settings


@pytest.mark.parametrize(
    ("value", "expected_result"), [("true", True), ("false", False), ("null", None), ("foo", "foo")]
)
async def test_sanitize_filter_value(value, expected_result):
    assert sanitize_filter_value(value) is expected_result


@pytest.mark.parametrize(
    ("uuid_value", "expected_result"),
    [
        (uuid.uuid1(), True),
        (uuid.uuid3(uuid.uuid4(), "test"), True),
        (uuid.uuid4(), True),
        (uuid.uuid5(uuid.uuid4(), "test"), True),
        ("invalid", False),
    ],
)
async def test_is_valid_uuid(uuid_value, expected_result):
    assert is_valid_uuid(str(uuid_value)) is expected_result


@pytest.mark.parametrize(
    ("value", "expected_result"),
    [
        ("1", True),
        ("-1", True),
        (str(uuid.uuid1()), False),
        (str(uuid.uuid4()), False),
        ("invalid", False),
    ],
)
def test_is_valid_int(value, expected_result):
    assert is_valid_int(value) is expected_result


@pytest.mark.parametrize(
    ("value", "expected_result"),
    [("1", True), ("-1", True), (1, True), (-1, True), (uuid.uuid1(), True), (uuid.uuid4(), True), ("invalid", False)],
)
async def test_is_valid_id(value, expected_result):
    assert is_valid_id(value) is expected_result


async def test_get_user_id_from_session_id(session_id):
    assert await get_user_id_from_session_id(None) is None
    assert await get_user_id_from_session_id("invalid") is None
    user_id = await get_user_id_from_session_id(session_id)
    assert user_id is not None

    now = datetime.now(timezone.utc)
    without_expired_session_id = jwt.encode(
        {
            "user_id": str(user_id),
        },
        settings.ADMIN_SECRET_KEY,
        algorithm="HS256",
    )
    assert await get_user_id_from_session_id(without_expired_session_id) is None

    session_expired_at = now - timedelta(seconds=settings.ADMIN_SESSION_EXPIRED_AT)
    expired_session_id = jwt.encode(
        {
            "user_id": str(user_id),
            "session_expired_at": session_expired_at.isoformat(),
        },
        settings.ADMIN_SECRET_KEY,
        algorithm="HS256",
    )
    assert await get_user_id_from_session_id(expired_session_id) is None

    session_expired_at = now + timedelta(seconds=settings.ADMIN_SESSION_EXPIRED_AT)
    invalid_user_session_id = jwt.encode(
        {
            "user_id": str(-1),
            "session_expired_at": session_expired_at.isoformat(),
        },
        settings.ADMIN_SECRET_KEY,
        algorithm="HS256",
    )
    assert await get_user_id_from_session_id(invalid_user_session_id) is None
