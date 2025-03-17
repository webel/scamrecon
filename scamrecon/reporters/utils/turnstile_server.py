"""
Standalone Turnstile Solver API

A lightweight Flask API for solving Cloudflare Turnstile challenges.
This can be integrated with scamrecon CLI tools.
"""

import argparse
import os
import random
import time
from typing import Any, Dict, Optional

import flask
import playwright.sync_api
import requests


class TurnstileSolverAPI:
    """Flask API for solving Turnstile challenges"""

    def __init__(self, host="127.0.0.1", port=5000, output_dir="turnstile_data"):
        self.host = host
        self.port = port
        self.output_dir = output_dir
        self.solver = None
        self.playwright_instance = None

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Initialize Flask app
        self.app = flask.Flask(__name__)
        self._register_routes()

    def _register_routes(self):
        """Register API routes"""

        @self.app.route("/")
        def index():
            return flask.redirect("https://github.com/YOUR_USERNAME/scamrecon")

        @self.app.route("/solve", methods=["POST"])
        def solve():
            try:
                # Get JSON data
                json_data = flask.request.json

                # Check for required fields
                if (
                    not json_data
                    or "sitekey" not in json_data
                    or "url" not in json_data
                ):
                    return (
                        flask.jsonify(
                            {
                                "status": "error",
                                "message": "Missing required fields: sitekey, url",
                            }
                        ),
                        400,
                    )

                # Extract parameters
                sitekey = json_data["sitekey"]
                url = json_data["url"]
                invisible = json_data.get("invisible", False)
                proxy = json_data.get("proxy")
                use_shared_browser = json_data.get("use_shared_browser", True)

                # Get or initialize the playwright instance
                if self.playwright_instance is None:
                    self.playwright_instance = playwright.sync_api.sync_playwright().start()
                
                start_time = time.time()
                print(f"Solving captcha for site {url} with proxy: {proxy}")

                # Create or reuse the solver instance
                if self.solver is None:
                    self.solver = PlaywrightTurnstileSolver(
                        playwright=self.playwright_instance,
                        output_dir=self.output_dir,
                        headless=False,
                        proxy=proxy,
                    )

                # Solve the captcha using the persistent browser instance
                token = self.solver.solve(url, sitekey, invisible)
                solve_time = time.time() - start_time
                print(f"Solve took {solve_time:.2f} seconds :: {token[:10]}...")

                # Return response - don't terminate the solver between requests
                return self._make_response(token)

            except Exception as e:
                print(f"Error solving turnstile: {str(e)}")
                return (
                    flask.jsonify(
                        {"status": "error", "message": str(e), "token": None}
                    ),
                    500,
                )

    def _make_response(self, token: str) -> flask.Response:
        """Create a standardized response"""
        if token == "failed":
            return flask.jsonify({"status": "error", "token": None})
        return flask.jsonify({"status": "success", "token": token})

    def run(self):
        """Run the API server"""
        print(f"Starting Turnstile Solver API on {self.host}:{self.port}")
        try:
            self.app.run(host=self.host, port=self.port)
        finally:
            # Clean up resources when the server shuts down
            if self.solver:
                self.solver.terminate()
            if self.playwright_instance:
                self.playwright_instance.stop()


class PlaywrightTurnstileSolver:
    """Playwright-based Turnstile solver for human intervention"""

    def __init__(
        self, playwright, output_dir="turnstile_data", headless=False, proxy=None
    ):
        """
        Initialize the Turnstile solver.

        Args:
            playwright: Playwright instance
            output_dir: Directory to store temporary files
            headless: Whether to run browser in headless mode
            proxy: Optional proxy to use
        """
        self.playwright = playwright
        self.output_dir = output_dir
        self.headless = headless
        self.proxy = proxy

        # Browser setup
        self._setup_browser()

    def _setup_browser(self):
        """Initialize the browser"""
        browser_type = self.playwright.chromium

        # Configure browser options
        browser_args = []
        if self.proxy:
            browser_args.append(f"--proxy-server={self.proxy}")

        # Launch browser - store a single browser instance to be reused
        if not hasattr(self, "browser") or not self.browser:
            self.browser = browser_type.launch(headless=self.headless, args=browser_args)

    def solve(self, url: str, sitekey: str, invisible: bool = False) -> str:
        """
        Solve a Turnstile challenge with human assistance

        Args:
            url: The URL containing the turnstile or any identifier string
            sitekey: The sitekey for the turnstile
            invisible: Whether the turnstile is invisible

        Returns:
            str: The solved token or "failed"
        """
        # Create a new browser context and page
        context = self.browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        )
        page = context.new_page()

        try:
            # Navigate to the URL or create a test page with the turnstile
            if url.startswith(("http://", "https://")):
                page.goto(url, wait_until="domcontentloaded")
            else:
                # Create temporary HTML with embedded turnstile
                temp_html = self._create_temp_html(sitekey, invisible)

                # Save to a temporary file
                temp_file = os.path.join(self.output_dir, f"turnstile_{sitekey}.html")
                with open(temp_file, "w") as f:
                    f.write(temp_html)

                # Use file:// URL
                page.goto(f"file://{os.path.abspath(temp_file)}")

            # Add a helpful overlay for the user
            self._add_user_overlay(page)

            # If it's invisible, try to trigger it
            if invisible:
                page.evaluate(
                    """() => {
                    if (typeof turnstile !== 'undefined') {
                        turnstile.render('#turnstile-wrapper');
                    }
                }"""
                )

            # Wait for the token to appear
            token = self._wait_for_token(page)

            if token:
                print(f"✓ Human-assisted solve successful! Token: {token[:10]}...")
                return token
            else:
                print("⨯ Human-assisted solve timed out or failed")
                return "failed"

        finally:
            # Clean up
            context.close()

    def _create_temp_html(self, sitekey: str, invisible: bool) -> str:
        """Create a temporary HTML page with the turnstile"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Turnstile Challenge</title>
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; }}
                h1 {{ color: #333; text-align: center; }}
                .container {{ max-width: 600px; margin: 0 auto; background: #f9f9f9; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .token-display {{ margin-top: 20px; word-break: break-all; background: #eee; padding: 10px; display: none; border-radius: 4px; }}
                .turnstile-container {{ display: flex; justify-content: center; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Scamrecon Turnstile Solver</h1>
                
                <div class="turnstile-container">
                    <div id="turnstile-wrapper" class="cf-turnstile" 
                         data-sitekey="{sitekey}" 
                         data-callback="javascriptCallback"
                         data-theme="light"
                         {'' if not invisible else 'data-size="invisible"'}>
                    </div>
                </div>
                
                <div id="token-display" class="token-display"></div>
                
                <script>
                    function javascriptCallback(token) {{
                        console.log("Turnstile token: " + token);
                        const displayElem = document.getElementById('token-display');
                        displayElem.style.display = 'block';
                        displayElem.innerText = "Token captured! Window will close automatically.";
                        
                        // Store token in multiple locations for reliable retrieval
                        localStorage.setItem('turnstileToken', token);
                        document.body.setAttribute('data-token', token);
                        window.turnstileToken = token;
                    }}
                </script>
            </div>
        </body>
        </html>
        """

    def _add_user_overlay(self, page):
        """Add a helpful overlay for the user"""
        page.evaluate(
            """() => {
            const messageDiv = document.createElement('div');
            messageDiv.style.position = 'fixed';
            messageDiv.style.top = '10px';
            messageDiv.style.left = '50%';
            messageDiv.style.transform = 'translateX(-50%)';
            messageDiv.style.background = '#f8d7da';
            messageDiv.style.color = '#721c24';
            messageDiv.style.padding = '10px 20px';
            messageDiv.style.borderRadius = '5px';
            messageDiv.style.zIndex = '10000';
            messageDiv.style.boxShadow = '0 2px 4px rgba(0,0,0,0.2)';
            messageDiv.innerHTML = '<b>Human Assistance Required</b><br>Please solve the Turnstile challenge<br>The window will auto-close when done';
            document.body.appendChild(messageDiv);
        }"""
        )

    def _wait_for_token(self, page, max_wait_time=600):
        """
        Wait for the turnstile token to appear

        Args:
            page: Playwright page
            max_wait_time: Maximum wait time in seconds

        Returns:
            str: Token if found, None otherwise
        """
        # Print instructions for the user
        print("\n" + "=" * 80)
        print(
            "HUMAN CAPTCHA REQUIRED - Please solve the Turnstile in the browser window"
        )
        print("Take your time - you have 10 minutes before timeout")
        print("The window will close automatically once the Turnstile is solved")
        print("=" * 80 + "\n")

        # Wait for the token
        start_time = time.time()
        token = None

        while time.time() - start_time < max_wait_time:
            # Check for token in various places
            token_checks = [
                "document.querySelector('#token-display')?.innerText",
                "localStorage.getItem('turnstileToken')",
                "document.body.getAttribute('data-token')",
                "window.turnstileToken",
                "document.querySelector('[name=\"cf-turnstile-response\"]')?.value",
                "document.querySelector('[data-cf-turnstile-response]')?.getAttribute('data-cf-turnstile-response')",
            ]

            for check in token_checks:
                try:
                    potential_token = page.evaluate(f"() => {{ return {check}; }}")
                    if (
                        potential_token
                        and len(potential_token) > 10
                        and "Token captured" not in potential_token
                    ):
                        token = potential_token
                        break
                except Exception:
                    pass

            if token:
                break

            # Countdown display
            elapsed = int(time.time() - start_time)
            if elapsed % 30 == 0 and elapsed > 0:  # Show message every 30 seconds
                remaining = max_wait_time - elapsed
                print(
                    f"Waiting for human to solve Turnstile... ({elapsed}s elapsed, {remaining}s remaining)"
                )

            # Short sleep to avoid hammering the CPU
            time.sleep(1)

        return token

    def terminate(self):
        """Close the browser and clean up resources"""
        if hasattr(self, "browser") and self.browser:
            self.browser.close()


def main():
    """Command-line entry point for the API server"""
    parser = argparse.ArgumentParser(description="Turnstile Solver API for scamrecon")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument(
        "--output-dir",
        default="turnstile_data",
        help="Directory to store temporary files",
    )

    args = parser.parse_args()

    # Create and run API
    api = TurnstileSolverAPI(host=args.host, port=args.port, output_dir=args.output_dir)
    api.run()


if __name__ == "__main__":
    main()
