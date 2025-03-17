"""
Browser utilities for handling Selenium browser instances with anti-detection features.
This module provides consistent browser configuration, cookie handling, and 
anti-detection measures used across the application.
"""

from .browser_manager import BrowserManager
from .stealth import apply_stealth_js, get_stealth_scripts

__all__ = ["BrowserManager", "apply_stealth_js", "get_stealth_scripts"]