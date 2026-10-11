"""Exercise the example's real MCP sessions with a fixture Ghidra backend."""

import asyncio
import importlib.util
import json
from pathlib import Path

import httpx
import pytest


@pytest.fixture
def example():
    path = Path(__file__).parents[1] / "examples" / "research_imports.py"
    spec = importlib.util.spec_from_file_location("research_imports", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configure_ghidra(backend):
    backend.ok("/health", {"capabilities": [], "program": {"name": "private-binary"}})
    backend.ok("/program_info", {"name": "private-binary", "sha256": "private-hash"})
    backend.ok("/imports", {
        "items": [{"name": "fopen", "library": "libc", "address": "private-address"}],
        "offset": 0, "limit": 100, "has_more": False, "total": 1,
    })


def mock_parallel(example, monkeypatch, *, search_error=False, fetch_error=False):
    requests = []

    def handle(request):
        message = json.loads(request.content)
        requests.append((request, message))
        method = message["method"]
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "initialize":
            result = {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}}, "serverInfo": {"name": "fixture", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": [
                {"name": name, "inputSchema": {"type": "object"}}
                for name in ("web_search", "web_fetch")
            ]}
        else:
            assert method == "tools/call"
            name = message["params"]["name"]
            if name == "web_search" and search_error:
                result = {"content": [{"type": "text", "text": "Search quota exhausted"}], "isError": True}
            else:
                data = {"results": [{"url": "https://example.org/fopen", "excerpts": ["fopen opens a stream"]}]}
                if name == "web_fetch":
                    data["errors"] = [{"url": "https://example.org/fopen", "error_type": "FETCH_FAILED"}] if fetch_error else []
                result = {"content": [{"type": "text", "text": json.dumps(data)}], "structuredContent": data}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})

    real_client = httpx.AsyncClient

    def client(**kwargs):
        assert kwargs["trust_env"] is False
        return real_client(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(example.httpx, "AsyncClient", client)
    return requests


def test_real_sessions_keep_local_results_out_of_remote_requests(example, fake_backend, monkeypatch, capsys):
    configure_ghidra(fake_backend)
    requests = mock_parallel(example, monkeypatch)
    args = example.build_parser().parse_args([
        "--ghidra-server", fake_backend.url, "--offset", "100",
        "--query", "POSIX fopen mode documentation", "--query", "fopen stream opening reference",
        "--fetch-url", "https://example.org/fopen",
    ])
    asyncio.run(example.run(args))
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [next(iter(section)) for section in output] == ["program", "imports", "search", "fetch"]
    assert output[0]["program"]["name"] == "private-binary"
    assert output[2]["search"]["results"][0]["excerpts"] == ["fopen opens a stream"]
    assert any(path == "/imports" and params["offset"] == "100" for _, path, params in fake_backend.requests)
    for request, message in requests:
        assert str(request.url) == example.PARALLEL_URL
        assert request.headers["User-Agent"] == example.USER_AGENT
        assert "Authorization" not in request.headers
        assert "private-" not in json.dumps(message)
    calls = [m["params"] for _, m in requests if m["method"] == "tools/call"]
    assert [c["name"] for c in calls] == ["web_search", "web_fetch"]
    assert calls[0]["arguments"]["search_queries"] == args.query
    assert calls[1]["arguments"]["urls"] == [args.fetch_url]
    assert calls[0]["arguments"]["session_id"] == calls[1]["arguments"]["session_id"]
    assert any(m["method"] == "tools/list" for _, m in requests)


def test_local_only_run_never_connects_to_parallel(example, fake_backend, monkeypatch, capsys):
    configure_ghidra(fake_backend)

    def no_remote(**kwargs):
        pytest.fail("A local-only run attempted to connect to Parallel")

    monkeypatch.setattr(example.httpx, "AsyncClient", no_remote)
    args = example.build_parser().parse_args(["--ghidra-server", fake_backend.url])
    asyncio.run(example.run(args))
    assert len(capsys.readouterr().out.splitlines()) == 2


def all_errors(error):
    return str(error) + " ".join(all_errors(e) for e in getattr(error, "exceptions", []))


@pytest.mark.parametrize("kind", ["ghidra", "search", "fetch"])
def test_failures_do_not_look_like_success(example, fake_backend, monkeypatch, kind):
    configure_ghidra(fake_backend)
    requests = mock_parallel(example, monkeypatch, search_error=kind == "search", fetch_error=kind == "fetch")
    if kind == "ghidra":
        fake_backend.fail("/program_info", 409, "NO_PROGRAM", "No program open")
    args = example.build_parser().parse_args([
        "--ghidra-server", fake_backend.url, "--query", "POSIX fopen mode documentation",
        "--fetch-url", "https://example.org/fopen",
    ])
    with pytest.raises(Exception) as caught:
        asyncio.run(example.run(args))
    expected = {"ghidra": "NO_PROGRAM", "search": "Search quota exhausted", "fetch": "Page fetching reported errors"}
    assert expected[kind] in all_errors(caught.value)
    if kind == "ghidra":
        assert requests == []
    elif kind == "search":
        assert not any(m.get("params", {}).get("name") == "web_fetch" for _, m in requests)
