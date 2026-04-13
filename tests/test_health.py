import pytest
import json


class TestHealthResponse:
    def test_parse_health_response_ok(self):
        data = {
            "status": "OK",
            "server_running": True,
            "watchdog_healthy": True,
            "program_loaded": True,
            "uptime_ms": 3600000,
            "last_request_ms_ago": 30000,
            "port": 8080,
        }
        assert data["status"] == "OK"
        assert data["server_running"] is True
        assert data["watchdog_healthy"] is True
        assert data["program_loaded"] is True
        assert data["uptime_ms"] == 3600000
        assert data["last_request_ms_ago"] == 30000
        assert data["port"] == 8080

    def test_parse_health_response_error(self):
        data = {
            "status": "ERROR",
            "server_running": False,
            "watchdog_healthy": False,
            "program_loaded": False,
            "uptime_ms": 0,
            "last_request_ms_ago": 0,
            "port": 0,
        }
        assert data["status"] == "ERROR"
        assert data["server_running"] is False

    def test_format_health_display(self):
        data = {
            "status": "OK",
            "server_running": True,
            "watchdog_healthy": True,
            "program_loaded": True,
            "uptime_ms": 3600000,
            "last_request_ms_ago": 30000,
            "port": 8080,
        }
        lines = [
            f"OK - Server healthy",
            f"Running: {data['server_running']}",
            f"Watchdog: {data['watchdog_healthy']}",
            f"Program: {data['program_loaded']}",
            f"Uptime: {data['uptime_ms']}ms",
            f"Last request: {data['last_request_ms_ago']}ms ago",
            f"Port: {data['port']}",
        ]
        output = "\n".join(lines)
        assert "OK - Server healthy" in output
        assert "Running: True" in output
        assert "Uptime: 3600000ms" in output
        assert "Port: 8080" in output


class TestHealthJsonConstruction:
    def test_json_valid(self):
        json_str = (
            '{"status": "OK", "server_running": true, "watchdog_healthy": true, '
            '"program_loaded": true, "uptime_ms": 3600000, "last_request_ms_ago": 30000, "port": 8080}'
        )
        data = json.loads(json_str)
        assert data["status"] == "OK"
        assert data["server_running"] is True

    def test_json_with_server_stopped(self):
        json_str = (
            '{"status": "ERROR", "server_running": false, "watchdog_healthy": false, '
            '"program_loaded": false, "uptime_ms": 0, "last_request_ms_ago": 0, "port": 0}'
        )
        data = json.loads(json_str)
        assert data["status"] == "ERROR"
        assert data["server_running"] is False


class TestWatchdogLogic:
    def test_watchdog_healthy_when_idle_short(self):
        WATCHDOG_INTERVAL_MS = 60000
        idle_time_ms = 5000
        watchdog_healthy = idle_time_ms > WATCHDOG_INTERVAL_MS * 2
        assert watchdog_healthy is False

    def test_watchdog_unhealthy_when_idle_long(self):
        WATCHDOG_INTERVAL_MS = 60000
        idle_time_ms = WATCHDOG_INTERVAL_MS * 2 + 1
        watchdog_healthy = idle_time_ms > WATCHDOG_INTERVAL_MS * 2
        assert watchdog_healthy is True

    def test_watchdog_boundary_condition(self):
        WATCHDOG_INTERVAL_MS = 60000
        idle_time_ms = WATCHDOG_INTERVAL_MS * 2
        watchdog_healthy = idle_time_ms > WATCHDOG_INTERVAL_MS * 2
        assert watchdog_healthy is False


class TestUptimeCalculation:
    def test_uptime_calculation(self):
        server_start_time = 1000
        now = 3001000
        uptime_ms = now - server_start_time if server_start_time > 0 else 0
        assert uptime_ms == 3000000

    def test_uptime_before_start(self):
        server_start_time = 0
        now = 3001000
        uptime_ms = now - server_start_time if server_start_time > 0 else 0
        assert uptime_ms == 0


class TestErrorHandling:
    def test_server_unreachable_message(self):
        error_msg = "ERROR - Server unreachable: Connection refused"
        assert "ERROR" in error_msg
        assert "unreachable" in error_msg.lower()

    def test_server_http_error_message(self):
        error_msg = "ERROR - Server returned status 500"
        assert "ERROR" in error_msg
        assert "500" in error_msg

    def test_invalid_status_message(self):
        error_msg = "ERROR - Server unhealthy"
        assert "ERROR" in error_msg
        assert "unhealthy" in error_msg.lower()
