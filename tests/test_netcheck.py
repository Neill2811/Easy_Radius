import pytest

from easy_radius.netcheck import main, ssh_client_allowed


def test_ssh_client_inside_admin_subnet():
    assert ssh_client_allowed("192.0.2.10", "192.0.2.0/24, 198.51.100.0/24")
    assert ssh_client_allowed("2001:db8::5", "2001:db8::/32")


def test_ssh_client_outside_admin_subnet_is_refused():
    assert not ssh_client_allowed("203.0.113.10", "192.0.2.0/24")
    assert not ssh_client_allowed("", "192.0.2.0/24")


def test_cli_exit_codes():
    assert main(["--ip", "192.0.2.10", "--subnets", "192.0.2.0/24"]) == 0
    assert main(["--ip", "203.0.113.10", "--subnets", "192.0.2.0/24"]) == 1
    assert main(["--ip", "not-an-ip", "--subnets", "192.0.2.0/24"]) == 2


def test_invalid_subnet_raises():
    with pytest.raises(ValueError):
        ssh_client_allowed("192.0.2.10", "not-a-subnet")
