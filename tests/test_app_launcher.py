"""The launcher's binding policy, tested before anything binds a socket.

`app.py` is the first thing an operator runs and the only file that decides which network
interfaces the unauthenticated console is reachable on. It previously defaulted to 0.0.0.0,
which silently published a no-auth API that will read any path the process can read. The
default is now loopback, and an off-loopback bind requires a second, explicit flag.

Nothing here starts a server: `uvicorn.run` is patched out, so these are pure policy checks.
"""
from unittest import mock

import pytest

import app


def test_default_bind_is_loopback_not_all_interfaces():
    """The safe value must be the one that happens when nobody reads the help text."""
    assert app.run_server.__defaults__[:3] == ("127.0.0.1", 8501, False)


def test_off_loopback_bind_without_the_flag_refuses_to_start():
    with pytest.raises(SystemExit) as exc:
        app.run_server(host="0.0.0.0", port=8501)
    message = str(exc.value)
    assert "refusing to bind" in message
    # The refusal must teach the operator the exact incantation, not just say no.
    assert "--allow-unauthenticated-public" in message
    assert "NO authentication" in message


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "10.0.0.5"])
def test_off_loopback_bind_with_the_flag_starts(host):
    with mock.patch("uvicorn.run") as run:
        app.run_server(host=host, port=9000, allow_unauthenticated_public=True)
    run.assert_called_once()
    assert run.call_args.kwargs["host"] == host


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_loopback_needs_no_flag(host):
    with mock.patch("uvicorn.run") as run:
        app.run_server(host=host, port=8501)
    run.assert_called_once()


def test_cli_refuses_host_0_0_0_0_alone():
    """The documented entry point must enforce the same rule as the function it wraps."""
    with mock.patch("uvicorn.run"), \
            mock.patch("sys.argv", ["app.py", "--host", "0.0.0.0"]), \
            pytest.raises(SystemExit) as exc:
        app.main()
    assert "refusing to bind" in str(exc.value)


def test_cli_with_both_flags_starts_the_server():
    with mock.patch("uvicorn.run") as run, \
            mock.patch("sys.argv", ["app.py", "--host", "0.0.0.0", "--port", "9100",
                                    "--allow-unauthenticated-public"]):
        app.main()
    run.assert_called_once()
    assert run.call_args.kwargs["host"] == "0.0.0.0"
    assert run.call_args.kwargs["port"] == 9100
