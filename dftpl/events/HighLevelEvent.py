from typing import Any, Optional, List, Dict
from dftpl.events.BaseEvent import BaseEvent
from datetime import datetime


class HighLevelEvent(BaseEvent):
    """High level event class"""
    
    def __init__(self):
        super().__init__()
        self.evidence_source: Optional[str] = None              # Source of the evidence
        self.description: Optional[str] = None                  # Human-readable description of the event
        self.category: Optional[str] = None                     # Category of the event for filtering
        self.device: Optional[str] = None                       # Device related to the event
        self.files: Optional[List[str]] = None                  # File related to the event
        self.trigger: Optional[ReasoningArtefact] = None        # Reasoning artefact that triggered the event
        self.supporting: Dict[str, List[Dict[str, Any]]] = {}   # List of reasoning artefacts supporting the event, five low level events before and after the event
        self.merged_id: List[int] = []                          # List of IDs of events that have been merged into this event
        self.date_time_iso: Optional[datetime] = None           # ISO 8601 formatted date time

    def add_time(self, date_time: str) -> None:
        """Sets the time for the event, adjusting min and max if necessary"""
        self.date_time_min = date_time
        self.date_time_max = date_time

    def set_keys(self, key: Any, value: Any) -> None:
        """Adds additional information to the event"""
        self.keys[key] = value

    def merge(self, event_id: int) -> None:
        """Adds an event ID to the list of merged events"""
        self.merged_id.append(event_id)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary for JSON serialization"""
        return {
            "id": self.id,
            "date_time_min": self.date_time_min,
            "date_time_max": self.date_time_max,
            "evidence_source": self.evidence_source,
            "type": self.type,
            "description": self.description,
            "category": self.category,
            "device": self.device,
            "files": self.files,
            "keys": self.keys,
            "trigger": self.trigger.to_dict() if self.trigger else None,
            "supporting": self.supporting,
            "merged_id": self.merged_id,
        }


class ReasoningArtefact:
    """Reasoning artefact class"""
    
    def __init__(self):
        self.id: Optional[str] = None                       # Unique identifier for the reasoning artefact
        self.description: Optional[str] = None              # Human-readable description of the reasoning artefact
        self.test_event: Optional[Dict[str, str]] = None    # The event that triggered the reasoning artefact
        self.provenance: Optional[Dict[str, Any]] = None    # Provenance details for traceability
        self.keys: Dict[str, Any] = {}                      # Additional key-value pairs with extra information
        self.references: Optional[List[str]] = None         # Reference to external sources

    def set_keys(self, key: Any, value: Any):
        # Adds additional information to the reasoning artefact
        self.keys[key] = value
    
    def add_time(self, date_time: str):
        # Sets the time for the event, adjusting min and max if necessary
        self.date_time_min = date_time
        self.date_time_max = date_time
    
    def to_dict(self) -> dict:
        # Converts the reasoning artefact to a dictionary
        if type(self.test_event) is not dict:
            test_event = {
                'type': self.test_event.type,
                'evidence': self.test_event.evidence
            },
        else:
            test_event = self.test_event
        
        reasoning_dict = {
            'id': self.id,
            'description': self.description,
            'test_event': test_event,
            'provenance': self.provenance,
            'keys': self.keys,
            'references': self.references
        }
        
        return reasoning_dict