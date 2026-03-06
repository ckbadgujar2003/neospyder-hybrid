from abc import ABC, abstractmethod

class BaseOEM(ABC):
    """Abstract base class for all vendor scrapers."""

    @abstractmethod
    def get_latest_advisory_url(self) -> str:
        """Return the URL of the latest advisory"""
        pass

    @abstractmethod
    def parse_advisory(self, url: str) -> dict:
        """Return the parsed advisory in a standard format"""
        pass
