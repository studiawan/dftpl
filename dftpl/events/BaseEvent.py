from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class BaseEvent(ABC):
    """Abstract base class for event types"""

    def __init__(self):
        self.id: Optional[Any] = None               # Unique identifier for the event (can be int or str)
        self.date_time_min: Optional[str] = None    # Earliest time the event could have occurred
        self.date_time_max: Optional[str] = None    # Latest time the event could have occurred
        self.type: Optional[str] = None             # Type of the event, e.g., 'Google Search', 'File Created', 'URL Visit'
        self.keys: Dict[str, Any] = {}              # Additional key-value pairs with extra information

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary for serialization"""
        pass
