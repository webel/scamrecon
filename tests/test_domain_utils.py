"""
Unit tests for the domain_utils module.
"""

import os
import tempfile
import pytest
from scamrecon.utils.domain_utils import (
    normalize_domain,
    is_valid_domain,
    extract_ips_from_text,
    load_domains_from_file
)


class TestNormalizeDomain:
    """Tests for the normalize_domain function."""
    
    def test_normalize_domain_basic(self):
        """Test basic domain normalization."""
        assert normalize_domain("example.com") == "example.com"
        
    def test_normalize_domain_with_protocol(self):
        """Test normalization of domains with protocols."""
        assert normalize_domain("https://example.com") == "example.com"
        assert normalize_domain("http://example.com") == "example.com"
        
    def test_normalize_domain_with_path(self):
        """Test normalization of domains with paths."""
        assert normalize_domain("example.com/path") == "example.com"
        assert normalize_domain("https://example.com/path") == "example.com"
        
    def test_normalize_domain_with_query(self):
        """Test normalization of domains with query parameters."""
        assert normalize_domain("example.com?query=123") == "example.com"
        assert normalize_domain("https://example.com?query=123") == "example.com"
        
    def test_normalize_domain_with_port(self):
        """Test normalization of domains with ports."""
        assert normalize_domain("example.com:8080") == "example.com"
        assert normalize_domain("https://example.com:8080") == "example.com"
        
    def test_normalize_domain_complex(self):
        """Test normalization with combinations of path, query, and port."""
        assert normalize_domain("https://example.com:8080/path?query=123") == "example.com"
        
    def test_normalize_domain_whitespace(self):
        """Test normalization with leading/trailing whitespace."""
        assert normalize_domain("  example.com  ") == "example.com"
        
    def test_normalize_domain_case(self):
        """Test that domain is converted to lowercase."""
        assert normalize_domain("EXAMPLE.COM") == "example.com"


class TestIsValidDomain:
    """Tests for the is_valid_domain function."""
    
    def test_valid_domains(self):
        """Test validation of valid domains."""
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.com") is True
        assert is_valid_domain("example.co.uk") is True
        assert is_valid_domain("xn--80aswg.xn--p1ai") is True  # IDN domain
        
    def test_invalid_domains(self):
        """Test validation of invalid domains."""
        assert is_valid_domain("") is False
        assert is_valid_domain("not_a_domain") is False
        assert is_valid_domain("example") is False
        assert is_valid_domain(".com") is False
        assert is_valid_domain("example.") is False
        
    def test_domains_with_protocols(self):
        """Test that domains with protocols are properly processed."""
        assert is_valid_domain("http://example.com") is True
        assert is_valid_domain("https://example.com") is True
        
    def test_domains_with_path(self):
        """Test that domains with paths are properly processed."""
        assert is_valid_domain("example.com/path") is True


class TestExtractIPsFromText:
    """Tests for the extract_ips_from_text function."""
    
    def test_extract_single_ip(self):
        """Test extraction of a single IP address."""
        text = "The server IP is 192.168.1.1"
        ips = extract_ips_from_text(text)
        assert ips == ["192.168.1.1"]
        
    def test_extract_multiple_ips(self):
        """Test extraction of multiple IP addresses."""
        text = "IPs: 192.168.1.1, 10.0.0.1, and 172.16.0.1"
        ips = extract_ips_from_text(text)
        assert set(ips) == {"192.168.1.1", "10.0.0.1", "172.16.0.1"}
        
    def test_extract_invalid_ips(self):
        """Test that invalid IPs are not extracted."""
        text = "Invalid IPs: 999.999.999.999, 256.0.0.1, 1.2.3"
        ips = extract_ips_from_text(text)
        assert ips == []
        
    def test_extract_ips_with_surrounding_text(self):
        """Test extraction of IPs surrounded by text."""
        text = "Server(192.168.1.1) and Client[10.0.0.1]"
        ips = extract_ips_from_text(text)
        assert set(ips) == {"192.168.1.1", "10.0.0.1"}
        
    def test_extract_no_ips(self):
        """Test with text containing no IP addresses."""
        text = "This text has no IP addresses."
        ips = extract_ips_from_text(text)
        assert ips == []


class TestLoadDomainsFromFile:
    """Tests for the load_domains_from_file function."""
    
    def test_load_domains_from_txt(self):
        """Test loading domains from a TXT file."""
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w+") as f:
            f.write("example.com\nexample.org\nexample.net\n")
            f.flush()
            
            domains = load_domains_from_file(f.name)
            assert domains == ["example.com", "example.org", "example.net"]
            
    def test_load_domains_from_csv(self):
        """Test loading domains from a CSV file."""
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w+") as f:
            f.write("id,domain,description\n")
            f.write("1,example.com,First domain\n")
            f.write("2,example.org,Second domain\n")
            f.flush()
            
            domains = load_domains_from_file(f.name)
            assert domains == ["example.com", "example.org"]
            
    def test_load_domains_with_skip_lines(self):
        """Test loading domains while skipping lines."""
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w+") as f:
            f.write("example.com\nexample.org\nexample.net\n")
            f.flush()
            
            domains = load_domains_from_file(f.name, skip_lines=1)
            assert domains == ["example.org", "example.net"]
            
    def test_load_domains_with_invalid_entries(self):
        """Test loading domains with some invalid entries."""
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w+") as f:
            f.write("example.com\nnot_a_domain\n.invalid\nexample.org\n")
            f.flush()
            
            domains = load_domains_from_file(f.name)
            assert "example.com" in domains
            assert "example.org" in domains
            assert "not_a_domain" not in domains
            assert ".invalid" not in domains