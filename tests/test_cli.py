import pytest

from ghidra_mcp.cli import build_parser


def test_defaults():
    args = build_parser().parse_args([])
    assert args.transport == "stdio"
    assert args.mcp_host == "127.0.0.1"
    assert args.timeout >= 60
    assert args.read_only is False


def test_streamable_http_transport_accepted():
    assert build_parser().parse_args(["--transport", "streamable-http"]).transport == "streamable-http"


def test_unknown_transport_rejected():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--transport", "websocket"])


@pytest.mark.parametrize("headless", [False, True])
@pytest.mark.parametrize("read_only", [False, True])
def test_read_only_reaches_server_in_both_modes(monkeypatch, tmp_path, headless, read_only):
    from types import SimpleNamespace
    from ghidra_mcp import cli
    from ghidra_mcp import headless as headless_module

    received = []
    backend = SimpleNamespace(health=lambda: None, base_url="http://127.0.0.1:1/")
    monkeypatch.setattr(cli, "GhidraBackend", lambda *args: backend)
    monkeypatch.setattr(cli, "create_server", lambda *args, **kwargs: received.append(kwargs))
    monkeypatch.setattr(cli, "serve", lambda *args: None)
    command = ["--read-only"] if read_only else []
    if headless:
        command += ["--headless", "--binary", str(tmp_path / "sample")]
        session = SimpleNamespace(start=lambda: None, run=lambda: None,
                                  close=lambda: None, request_stop=lambda: None)
        monkeypatch.setattr(headless_module, "HeadlessSession", lambda *args: session)
        monkeypatch.setattr(headless_module, "protect_stdout", lambda: None)
        # Run the mocked server thread synchronously; never create a JVM or exit pytest.
        monkeypatch.setattr(cli.threading, "Thread", lambda **kw: SimpleNamespace(start=kw["target"]))
        monkeypatch.setattr(cli.os, "_exit", lambda code: None)
    cli.main(command)
    assert len(received) == 1
    assert received[0]["read_only"] is read_only
