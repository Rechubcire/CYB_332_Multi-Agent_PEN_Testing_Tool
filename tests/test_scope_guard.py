"""
Runs test on scope_guard.py to make sure all
of the methods run as intended
"""

import pytest
from src.core.scope_guard import is_in_scope, enforce_scope, validate_port_range, ScopeViolationError
"""
Tests to make sure is_in_scope work properly
"""
# Exact host in subnet
def test_exact_host_in_scope():
    assert is_in_scope("192.168.56.101", "192.168.56.101/32") == True

# Different host same subnet out of scope
def test_different_host_same_subnet_out_of_scope():
    assert is_in_scope("192.168.56.102", "192.168.56.101/32") == False

# Public IP out of scope
def test_public_host_out_of_scope():
    assert is_in_scope("8.8.8.8", "192.168.56.101/32") == False
    assert is_in_scope("1.1.1.1", "192.168.56.101/32") == False
    assert is_in_scope("10.0.0.1", "192.168.56.101/32") == False

# IP is in subnet scope
def test_ip_in_subnet_scope():
    # /24 subnet scope means all addresses 192.168.56.x are in scope
    assert is_in_scope("192.168.56.1", "192.168.56.101/24") == True
    assert is_in_scope("192.168.56.101", "192.168.56.101/24") == True
    assert is_in_scope("192.168.56.254", "192.168.56.101/24") == True

# IP is out of subnet scope
def test_ip_out_of_subnet_scope():
    assert is_in_scope("192.168.55.1", "192.168.56.101/24") == False
    assert is_in_scope("192.168.57.101", "192.168.56.101/24") == False

# Incorrect IP formatting
def test_malformed_ip():
    assert is_in_scope("not-an-ip", "192.168.56.101/32") == False
    assert is_in_scope("123.1234..1", "192.168.56.101/32") == False
    assert is_in_scope("", "192.168.56.101/32") == False

# Incorrect subnet scope formatting
def test_malformed_subnet():
    assert is_in_scope("192.168.56.101", "not-a-cidr") == False
    assert is_in_scope("192.168.56.101", "199.1.234.1/100") == False
    assert is_in_scope("192.168.56.101", "") == False

"""
Tests to make sure that enforce_scope() works
"""

# Valid target_ip and scope_cidr
def test_valid_target_ip_and_scope():
    enforce_scope("192.168.56.101", "192.168.56.101/32")

# Target IP out of scope raises error
def test_target_ip_raises_error():
    with pytest.raises(ScopeViolationError):
        enforce_scope("192.168.50.1", "192.168.56.101/32")

# Out of scope target_ip is included in error message
def test_enforce_scope_errormessage_contains_target_ip():
    try:
        enforce_scope("8.8.8.8", "192.168.56.101/32")
    except ScopeViolationError as e:
        assert "8.8.8.8" in str(e)

# Catch the exception with except
def test_scope_violation_exception_subclass():
    with pytest.raises(Exception):
        enforce_scope("8.8.8.8", "192.168.56.101/32")

"""
Tests to make sure validate_port_range() works
"""

# Valid full range
def test_valid_full_range():
    assert validate_port_range("1-65535") == True

# Valid partial range
def test_valid_partial_range():
    assert validate_port_range("200-800") == True
    assert validate_port_range("1-5000") == True

# Valid single port
def test_valid_single_port():
    assert validate_port_range("443") == True
    assert validate_port_range("80") == True

# Invalid out of range
def test_invalid_out_of_range():
    assert validate_port_range("0-65535") == False
    assert validate_port_range("1-99999") == False

# Reversed port range
def test_reversed_port_range():
    assert validate_port_range("1234-80") == False

# Non integer port
def test_non_int_port():
    assert validate_port_range("not-an-int") == False
    assert validate_port_range("80-int") == False