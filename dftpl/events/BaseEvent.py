# /events/BaseEvent.py

from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class BaseEvent(ABC):
    """Abstract base class for event types"""

    def __init__(self):
        self.id: Optional[Any] = None               
        self.date_time_min: Optional[str] = None    
        self.date_time_max: Optional[str] = None    
        self.type: Optional[str] = None             
        self.keys: Dict[str, Any] = {}              

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary for serialization"""
        pass
