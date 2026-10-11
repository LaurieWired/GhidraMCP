import pytest

from ghidra_mcp.cli import build_parser


def test_defaults():
    args = build_parser().parse_args([])
    assert args.transport == "stdio"
    assert args.mcp_host == "127.0.0.1"
    assert args.timeout >= 60


def test_streamable_http_transport_accepted():
    assert build_parser().parse_args(["--transport", "streamable-http"]).transport == "streamable-http"


def test_unknown_transport_rejected():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--transport", "websocket"])
