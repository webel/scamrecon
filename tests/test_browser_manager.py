"""
Unit tests for the BrowserManager class.
These tests use pytest-mock to avoid launching real browsers during testing.
"""

import os
import tempfile
import pickle
import pytest
from unittest.mock import MagicMock, patch
from selenium.webdriver.common.by import By

from scamrecon.utils.browser import BrowserManager


@pytest.fixture
def mock_driver():
    """Fixture to provide a mock Selenium driver."""
    mock = MagicMock()
    mock.current_url = "https://example.com"
    mock.page_source = "<html><body>Test page</body></html>"
    return mock


@pytest.fixture
def mock_wait():
    """Fixture to provide a mock WebDriverWait."""
    return MagicMock()


@pytest.fixture
def browser_manager(mock_driver, mock_wait):
    """Fixture to provide a BrowserManager with mocked components."""
    with patch('scamrecon.utils.browser.BrowserManager.setup_driver') as mock_setup:
        manager = BrowserManager(headless=True, timeout=10)
        manager.driver = mock_driver
        manager.wait = mock_wait
        return manager


class TestBrowserManager:
    """Tests for the BrowserManager class."""

    def test_initialization(self):
        """Test basic initialization of BrowserManager."""
        browser = BrowserManager(headless=True, timeout=15)
        assert browser.headless is True
        assert browser.timeout == 15
        assert browser.driver is None
        assert browser.wait is None

    def test_setup_driver(self, browser_manager):
        """Test driver setup with mocked dependencies."""
        with patch('undetected_chromedriver.Chrome') as mock_chrome, \
             patch('scamrecon.utils.browser.apply_stealth_js') as mock_stealth:
            
            # Reset driver to None for the test
            browser_manager.driver = None
            
            # Mock Chrome instance
            mock_driver = MagicMock()
            mock_chrome.return_value = mock_driver
            
            # Call setup_driver
            result = browser_manager.setup_driver()
            
            # Verify Chrome was initialized with correct options
            mock_chrome.assert_called_once()
            
            # Verify stealth JS was applied
            mock_stealth.assert_called_once_with(mock_driver)
            
            # Verify timeouts were set
            assert mock_driver.set_page_load_timeout.called
            assert mock_driver.set_script_timeout.called
            
            # Verify result is the driver
            assert result == mock_driver

    def test_navigate_to(self, browser_manager):
        """Test navigation functionality."""
        url = "https://example.com"
        result = browser_manager.navigate_to(url, wait_time=0)
        
        # Verify driver was called to navigate
        browser_manager.driver.get.assert_called_once_with(url)
        
        # Verify result is True on success
        assert result is True

    def test_navigate_to_error(self, browser_manager):
        """Test navigation with error handling."""
        # Make the get method raise an exception
        browser_manager.driver.get.side_effect = Exception("Navigation failed")
        
        url = "https://example.com"
        result = browser_manager.navigate_to(url, wait_time=0)
        
        # Verify result is False on error
        assert result is False

    def test_fill_form_field(self, browser_manager):
        """Test form field filling functionality."""
        # Mock the WebDriverWait().until() to return a field element
        field_element = MagicMock()
        browser_manager.wait.until.return_value = field_element
        
        # Test filling a field
        result = browser_manager.fill_form_field((By.ID, "username"), "testuser", clear_first=True)
        
        # Verify waiter was called
        browser_manager.wait.until.assert_called_once()
        
        # Verify field was cleared
        field_element.clear.assert_called_once()
        
        # Verify field was filled (each character sent)
        assert field_element.send_keys.call_count == len("testuser")
        
        # Verify result is True on success
        assert result is True

    def test_save_cookies(self, browser_manager):
        """Test cookie saving functionality."""
        # Setup test
        browser_manager.cookie_file = tempfile.mktemp(suffix=".pkl")
        browser_manager.driver.get_cookies.return_value = [{"name": "test", "value": "value"}]
        browser_manager.driver.execute_script.side_effect = [
            ["key1", "key2"],  # Keys for localStorage
            "value1",          # Value for key1
            "value2",          # Value for key2
            ["key3"],          # Keys for sessionStorage
            "value3"           # Value for key3
        ]
        
        # Test cookie saving
        try:
            result = browser_manager.save_cookies()
            
            # Verify cookies were requested
            browser_manager.driver.get_cookies.assert_called_once()
            
            # Verify localStorage and sessionStorage were checked
            assert browser_manager.driver.execute_script.call_count >= 3
            
            # Verify cookies were saved
            assert os.path.exists(browser_manager.cookie_file)
            
            # Load saved cookies to verify content
            with open(browser_manager.cookie_file, "rb") as f:
                saved_data = pickle.load(f)
                
            assert "cookies" in saved_data
            assert saved_data["cookies"] == [{"name": "test", "value": "value"}]
            assert "local_storage" in saved_data
            assert "session_storage" in saved_data
            
            # Verify result is True on success
            assert result is True
            
        finally:
            # Clean up
            if os.path.exists(browser_manager.cookie_file):
                os.remove(browser_manager.cookie_file)

    def test_close(self, browser_manager):
        """Test browser closing functionality."""
        browser_manager.close()
        browser_manager.driver.quit.assert_called_once()
        
    def test_context_manager(self, browser_manager):
        """Test the context manager pattern."""
        with patch('scamrecon.utils.browser.BrowserManager.setup_driver') as mock_setup, \
             patch('scamrecon.utils.browser.BrowserManager.close') as mock_close:
            
            # Reset driver for this test
            browser_manager.driver = None
            mock_setup.return_value = MagicMock()
            
            # Use context manager
            with browser_manager as browser:
                # Verify setup was called
                mock_setup.assert_called_once()
                
                # Do something with the browser
                browser.navigate_to("https://example.com")
                
            # Verify close was called
            mock_close.assert_called_once()