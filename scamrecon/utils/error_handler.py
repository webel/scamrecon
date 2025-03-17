"""
Standardized error handling utilities for consistent error management.
"""

import logging
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from rich.console import Console


class ErrorHandler:
    """
    Standardized error handling for consistent error management across the application.
    """
    
    def __init__(self, logger_name: str = "scamrecon", use_rich: bool = True):
        """
        Initialize the error handler.
        
        Args:
            logger_name: Name of the logger to use
            use_rich: Whether to use rich for console output
        """
        self.logger = logging.getLogger(logger_name)
        self.use_rich = use_rich
        
        if use_rich:
            self.console = Console()
        
    def log(self, message: str, level: str = "info", exc_info: bool = False):
        """
        Log a message with consistent formatting.
        
        Args:
            message: Message to log
            level: Log level (debug, info, warning, error, critical)
            exc_info: Whether to include exception info
        """
        # Determine log level
        if level.lower() == "debug":
            self.logger.debug(message, exc_info=exc_info)
        elif level.lower() == "info":
            self.logger.info(message, exc_info=exc_info)
        elif level.lower() == "warning":
            self.logger.warning(message, exc_info=exc_info)
        elif level.lower() == "error":
            self.logger.error(message, exc_info=exc_info)
        elif level.lower() == "critical":
            self.logger.critical(message, exc_info=exc_info)
        
        # Console output with rich if enabled
        if self.use_rich:
            if level.lower() == "debug":
                self.console.print(f"[dim]{message}[/dim]")
            elif level.lower() == "info":
                self.console.print(message)
            elif level.lower() == "warning":
                self.console.print(f"[yellow]⚠ {message}[/yellow]")
            elif level.lower() == "error":
                self.console.print(f"[red]✗ {message}[/red]")
            elif level.lower() == "critical":
                self.console.print(f"[bold red]!!! {message} !!![/bold red]")
            elif level.lower() == "success":
                self.console.print(f"[green]✓ {message}[/green]")
        else:
            # Fallback to print
            prefix = {
                "debug": "DEBUG: ",
                "info": "",
                "warning": "WARNING: ",
                "error": "ERROR: ",
                "critical": "CRITICAL: ",
                "success": "SUCCESS: "
            }.get(level.lower(), "")
            
            print(f"{prefix}{message}")
    
    def handle_exception(
        self, 
        e: Exception, 
        context: str = "", 
        log_level: str = "error",
        reraise: bool = False
    ):
        """
        Handle an exception with consistent logging.
        
        Args:
            e: The exception to handle
            context: Context info about where the exception occurred
            log_level: Log level to use
            reraise: Whether to reraise the exception after handling
            
        Raises:
            Exception: The original exception if reraise is True
        """
        # Format the error message
        error_type = type(e).__name__
        error_msg = str(e)
        
        if context:
            message = f"{context}: {error_type} - {error_msg}"
        else:
            message = f"{error_type} - {error_msg}"
            
        # Log the error
        self.log(message, level=log_level, exc_info=True)
        
        # Add stack trace for critical errors
        if log_level.lower() in ("critical", "error"):
            stack_trace = traceback.format_exc()
            self.logger.debug(f"Stack trace:\n{stack_trace}")
            
        # Reraise if requested
        if reraise:
            raise e
    
    def retry(
        self, 
        func: Callable, 
        args: Tuple = (), 
        kwargs: Dict = None, 
        max_retries: int = 3, 
        retry_delay: int = 1,
        context: str = ""
    ) -> Any:
        """
        Retry a function with exponential backoff.
        
        Args:
            func: Function to retry
            args: Arguments to pass to the function
            kwargs: Keyword arguments to pass to the function
            max_retries: Maximum number of retries
            retry_delay: Initial delay between retries (will increase exponentially)
            context: Context info for error messages
            
        Returns:
            Any: The result of the function if successful
            
        Raises:
            Exception: The last exception if all retries fail
        """
        import time
        
        if kwargs is None:
            kwargs = {}
            
        attempt = 0
        last_exception = None
        
        while attempt < max_retries:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                attempt += 1
                last_exception = e
                
                # Calculate delay with exponential backoff
                delay = retry_delay * (2 ** (attempt - 1))
                
                if attempt < max_retries:
                    retry_context = f"{context} (Retry {attempt}/{max_retries})"
                    self.log(
                        f"{retry_context}: {type(e).__name__} - {str(e)}. Retrying in {delay}s...",
                        level="warning"
                    )
                    time.sleep(delay)
                else:
                    # Last attempt failed
                    final_context = f"{context} (Failed after {max_retries} attempts)"
                    self.handle_exception(e, context=final_context, reraise=True)
        
        # Should never reach here, but just in case
        raise last_exception