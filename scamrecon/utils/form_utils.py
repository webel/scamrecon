"""
Utilities for form handling and submission.
"""

import random
import time
from typing import Dict, List, Optional, Tuple, Union, Any

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException


def extract_form_fields(driver) -> Dict[str, str]:
    """
    Extract all form fields from a page.
    
    Args:
        driver: Selenium WebDriver instance
        
    Returns:
        Dict[str, str]: Dictionary of form field names and values
    """
    form_fields = {}
    
    try:
        # Find all input fields
        input_fields = driver.find_elements(By.CSS_SELECTOR, "input:not([type='hidden'])")
        for field in input_fields:
            field_name = field.get_attribute("name")
            field_value = field.get_attribute("value")
            if field_name:
                form_fields[field_name] = field_value or ""
                
        # Find all textarea fields
        textarea_fields = driver.find_elements(By.CSS_SELECTOR, "textarea")
        for field in textarea_fields:
            field_name = field.get_attribute("name")
            field_value = field.get_attribute("value")
            if field_name:
                form_fields[field_name] = field_value or ""
                
        # Find all select fields
        select_fields = driver.find_elements(By.CSS_SELECTOR, "select")
        for field in select_fields:
            field_name = field.get_attribute("name")
            selected_option = field.find_elements(By.CSS_SELECTOR, "option[selected]")
            field_value = ""
            if selected_option:
                field_value = selected_option[0].get_attribute("value")
            if field_name:
                form_fields[field_name] = field_value or ""
                
        return form_fields
        
    except Exception as e:
        print(f"Error extracting form fields: {e}")
        return form_fields


def fill_form(driver, form_data: Dict[str, str], natural_typing: bool = True) -> Dict[str, bool]:
    """
    Fill form fields with data and optional natural typing.
    
    Args:
        driver: Selenium WebDriver instance
        form_data: Dictionary of field names and values
        natural_typing: Whether to simulate natural typing patterns
        
    Returns:
        Dict[str, bool]: Dictionary of field names and success status
    """
    results = {}
    
    # Get all fields on the page
    all_inputs = driver.find_elements(By.CSS_SELECTOR, "input:not([type='hidden'])")
    all_textareas = driver.find_elements(By.CSS_SELECTOR, "textarea")
    all_selects = driver.find_elements(By.CSS_SELECTOR, "select")
    
    # Process all form fields
    for field_name, field_value in form_data.items():
        if not field_value:
            # Skip empty values
            results[field_name] = True
            continue
            
        try:
            # Try to find the field by name
            field = None
            
            # Search in inputs
            for input_field in all_inputs:
                if input_field.get_attribute("name") == field_name:
                    field = input_field
                    break
                    
            # Search in textareas if not found
            if not field:
                for textarea in all_textareas:
                    if textarea.get_attribute("name") == field_name:
                        field = textarea
                        break
                        
            # Search in selects if not found
            if not field:
                for select in all_selects:
                    if select.get_attribute("name") == field_name:
                        field = select
                        break
            
            # If field was found, fill it
            if field:
                # Handle different field types
                field_type = field.get_attribute("type") if field.tag_name == "input" else field.tag_name
                
                if field_type == "checkbox":
                    # For checkboxes, check or uncheck based on value
                    current_state = field.is_selected()
                    desired_state = field_value.lower() in ("true", "yes", "1", "on")
                    
                    if current_state != desired_state:
                        field.click()
                        
                elif field_type == "radio":
                    # For radio buttons, find and click the correct option
                    radio_group = driver.find_elements(
                        By.CSS_SELECTOR, f"input[type='radio'][name='{field_name}']"
                    )
                    for radio in radio_group:
                        if radio.get_attribute("value") == field_value:
                            radio.click()
                            break
                            
                elif field_type == "select":
                    # For select fields, choose the option
                    options = field.find_elements(By.TAG_NAME, "option")
                    for option in options:
                        if option.get_attribute("value") == field_value:
                            option.click()
                            break
                            
                else:
                    # For text inputs and textareas
                    field.clear()
                    
                    if natural_typing:
                        # Type with natural rhythm
                        for char in field_value:
                            field.send_keys(char)
                            time.sleep(random.uniform(0.05, 0.15))
                            
                            # Occasionally pause typing as if thinking
                            if random.random() < 0.05:  # 5% chance
                                time.sleep(random.uniform(0.2, 0.6))
                                
                        # Small pause after completing field
                        time.sleep(random.uniform(0.3, 0.7))
                    else:
                        # Fast typing
                        field.send_keys(field_value)
                        
                results[field_name] = True
            else:
                # Field not found
                results[field_name] = False
                print(f"Warning: Field '{field_name}' not found on page")
                
        except Exception as e:
            results[field_name] = False
            print(f"Error filling field '{field_name}': {e}")
            
    return results


def wait_for_form_validation(driver, max_wait: int = 10) -> bool:
    """
    Wait for form validation to complete.
    
    Args:
        driver: Selenium WebDriver instance
        max_wait: Maximum time to wait in seconds
        
    Returns:
        bool: True if validation completed, False on timeout
    """
    def is_validation_complete():
        # Check for any validation spinners
        spinners = driver.find_elements(
            By.CSS_SELECTOR, 
            ".spinner, .loading, [data-loading], .validating, .processing"
        )
        
        # If no spinners are visible, validation is complete
        return len([s for s in spinners if s.is_displayed()]) == 0
    
    try:
        # Initially wait a short time for validation to start
        time.sleep(0.5)
        
        # Create wait object
        wait = WebDriverWait(driver, max_wait)
        
        # Wait for validation to complete
        wait.until(lambda d: is_validation_complete())
        return True
    except TimeoutException:
        print(f"Timed out waiting for form validation after {max_wait} seconds")
        return False
    except Exception as e:
        print(f"Error waiting for form validation: {e}")
        return False


def is_submit_button_enabled(driver) -> bool:
    """
    Check if the submit button is enabled.
    
    Args:
        driver: Selenium WebDriver instance
        
    Returns:
        bool: True if submit button is enabled, False otherwise
    """
    try:
        # Find all submit buttons
        submit_buttons = driver.find_elements(
            By.CSS_SELECTOR, 
            "button[type='submit'], input[type='submit']"
        )
        
        # If any submit button is enabled, return True
        for button in submit_buttons:
            if not button.get_attribute("disabled"):
                return True
                
        return False
    except Exception as e:
        print(f"Error checking submit button state: {e}")
        return False


def wait_for_field_availability(driver, field_selector, timeout: int = 10) -> bool:
    """
    Wait for a field to become available (clickable).
    
    Args:
        driver: Selenium WebDriver instance
        field_selector: CSS or By selector tuple for the field
        timeout: Maximum time to wait in seconds
        
    Returns:
        bool: True if field became available, False on timeout
    """
    try:
        WebDriverWait(driver, timeout).until(
            EC.element_to_be_clickable(field_selector)
        )
        return True
    except TimeoutException:
        print(f"Timed out waiting for field {field_selector} to become clickable")
        return False
    except Exception as e:
        print(f"Error waiting for field {field_selector}: {e}")
        return False