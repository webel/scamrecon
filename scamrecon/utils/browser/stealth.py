"""
JavaScript utilities for anti-detection measures when using Selenium.
These utilities help prevent websites from detecting automation tools.
"""

def get_stealth_scripts():
    """
    Get a dictionary of all stealth JavaScript snippets.
    
    Returns:
        dict: A dictionary with named stealth scripts
    """
    return {
        "basic_stealth": """
            // Remove automation flags
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
            
            // Mimic normal chrome
            window.chrome = {
                runtime: {},
                loadTimes: function() {},
                csi: function() {},
                app: {}
            };
            
            // Fix iframe detection
            const originalAttachShadow = Element.prototype.attachShadow;
            Element.prototype.attachShadow = function() {
                return originalAttachShadow.apply(this, arguments);
            };
        """,
        
        "advanced_stealth": """
            // Advanced anti-detection techniques
            
            // Fix hairline feature by overriding its detection
            const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                // Spoof renderer info
                if (parameter === 37445) {
                    return 'Intel Inc.';
                }
                if (parameter === 37446) {
                    return 'Intel Iris OpenGL Engine';
                }
                return originalGetParameter.call(this, parameter);
            };
            
            // Spoof screen resolution
            if (window.screen) {
                const originalWidth = window.screen.width;
                const originalHeight = window.screen.height;
                const originalAvailWidth = window.screen.availWidth;
                const originalAvailHeight = window.screen.availHeight;
                const originalColorDepth = window.screen.colorDepth;
                const originalPixelDepth = window.screen.pixelDepth;
                
                // Add a tiny bit of randomness to make it look like a normal device
                const offsetWidth = Math.floor(Math.random() * 10);
                const offsetHeight = Math.floor(Math.random() * 10);
                
                Object.defineProperty(window.screen, 'width', { get: () => originalWidth - offsetWidth });
                Object.defineProperty(window.screen, 'height', { get: () => originalHeight - offsetHeight });
                Object.defineProperty(window.screen, 'availWidth', { get: () => originalAvailWidth - offsetWidth });
                Object.defineProperty(window.screen, 'availHeight', { get: () => originalAvailHeight - offsetHeight });
                Object.defineProperty(window.screen, 'colorDepth', { get: () => 24 });
                Object.defineProperty(window.screen, 'pixelDepth', { get: () => 24 });
            }
            
            // Hide automation plugins
            const originalPlugins = navigator.plugins;
            const pluginsLength = originalPlugins.length;
            Object.defineProperty(navigator, 'plugins', {
                get: () => {
                    Object.defineProperty(originalPlugins, 'length', {
                        get: () => pluginsLength || 5
                    });
                    return originalPlugins;
                }
            });
            
            // Modify navigator properties to avoid fingerprinting
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en', 'es']
            });
            
            // Override permission behavior
            const originalQuery = navigator.permissions.query;
            navigator.permissions.query = function(parameters) {
                return originalQuery.call(this, parameters)
                    .then(function(result) {
                        if (parameters.name === 'notifications') {
                            // Return "prompt" instead of "denied" to look more like a regular user
                            Object.defineProperty(result, 'state', {
                                get: () => 'prompt'
                            });
                        }
                        return result;
                    });
            };
        """
    }


def apply_stealth_js(driver, scripts=None):
    """
    Apply stealth JavaScript to the browser to avoid detection.
    
    Args:
        driver: Selenium WebDriver instance
        scripts: List of script names to apply, or None for all scripts
    
    Returns:
        bool: True if successful
    """
    if not driver:
        return False
        
    all_scripts = get_stealth_scripts()
    
    if scripts is None:
        # Apply basic stealth by default
        scripts = ["basic_stealth"]
    
    try:
        for script_name in scripts:
            if script_name in all_scripts:
                driver.execute_script(all_scripts[script_name])
            else:
                print(f"Warning: Stealth script '{script_name}' not found")
        
        return True
    except Exception as e:
        print(f"Error applying stealth scripts: {e}")
        return False