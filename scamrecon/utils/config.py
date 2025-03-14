"""
Configuration management for API keys and settings.
"""
import os
from dataclasses import dataclass
from typing import Dict, Optional

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


@dataclass
class APIKeys:
    virustotal: Optional[str] = None
    securitytrails: Optional[str] = None
    shodan: Optional[str] = None
    abuseipdb: Optional[str] = None
    urlscan: Optional[str] = None
    
    @classmethod
    def from_env(cls):
        """Load API keys from environment variables"""
        return cls(
            virustotal=os.getenv("VIRUSTOTAL_API_KEY"),
            securitytrails=os.getenv("SECURITYTRAILS_API_KEY"),
            shodan=os.getenv("SHODAN_API_KEY"),
            abuseipdb=os.getenv("ABUSEIPDB_API_KEY"),
            urlscan=os.getenv("URLSCAN_API_KEY"),
        )
    
    def to_dict(self) -> Dict[str, Optional[str]]:
        """Convert to dictionary"""
        return {
            "virustotal": self.virustotal,
            "securitytrails": self.securitytrails,
            "shodan": self.shodan,
            "abuseipdb": self.abuseipdb,
            "urlscan": self.urlscan,
        }


@dataclass
class Config:
    """Application configuration"""
    api_keys: APIKeys
    timeout: int = 10
    verbose: bool = False
    scan_malware: bool = True
    output_dir: str = "results"
    
    @classmethod
    def load_default(cls):
        """Load default configuration"""
        return cls(api_keys=APIKeys.from_env())