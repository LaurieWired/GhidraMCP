import pytest

from ghidra_mcp.backend import BackendError, DeferredBackend, GhidraBackend


def test_success_returns_data(fake_backend):
    fake_backend.ok("/program_info", {"name": "a.out"})
    assert GhidraBackend(fake_backend.url).get("program_info") == {"name": "a.out"}


def test_error_envelope_raises_with_code(fake_backend):
    fake_backend.fail("/function", 404, "FUNCTION_NOT_FOUND", "No function at 0x10")
    with pytest.raises(BackendError) as info:
        GhidraBackend(fake_backend.url).get("function", address="0x10")
    assert info.value.code == "FUNCTION_NOT_FOUND"
    assert info.value.status == 404
    assert "0x10" in str(info.value)


def test_plain_text_response_is_reported_as_old_plugin(fake_backend):
    fake_backend.routes["/functions"] = (200, "main at 00401000")
    with pytest.raises(BackendError) as info:
        GhidraBackend(fake_backend.url).get("functions")
    assert info.value.code == "BAD_RESPONSE"


def test_unreachable_backend():
    with pytest.raises(BackendError) as info:
        GhidraBackend("http://127.0.0.1:1/", connect_timeout=0.5).get("health")
    assert info.value.code == "BACKEND_UNAVAILABLE"


def test_none_params_are_dropped_and_post_is_form_encoded(fake_backend):
    fake_backend.ok("/rename_variable", {})
    GhidraBackend(fake_backend.url).post(
        "rename_variable", function_address="0x1", function_name=None, old_name="a", new_name="b"
    )
    method, path, params = fake_backend.requests[-1]
    assert (method, path) == ("POST", "/rename_variable")
    assert params == {"function_address": "0x1", "old_name": "a", "new_name": "b"}


def test_health_returns_none_when_unreachable():
    assert GhidraBackend("http://127.0.0.1:1/").health(timeout=0.5) is None


def test_deferred_backend_not_ready():
    backend = DeferredBackend(1, 1, wait_timeout=0.05)
    with pytest.raises(BackendError) as info:
        backend.get("program_info")
    assert info.value.code == "NOT_READY"


def test_deferred_backend_failure_is_reported():
    backend = DeferredBackend(1, 1, wait_timeout=0.05)
    backend.set_failed("LoadException: bad file")
    with pytest.raises(BackendError) as info:
        backend.get("program_info")
    assert info.value.code == "HEADLESS_FAILED"
    assert "bad file" in info.value.message


def test_deferred_backend_ready(fake_backend):
    fake_backend.ok("/program_info", {"name": "x"})
    backend = DeferredBackend(1, 5, wait_timeout=0.05)
    backend.set_ready(fake_backend.url)
    assert backend.get("program_info") == {"name": "x"}
