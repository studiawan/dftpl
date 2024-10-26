from typing import Any


class HighLevelEvent:
    """High level event class"""
    def __init__(self):
        self.id = None              # Unique identifier for the event
        self.date_time_min = None   # Earliest time the event could have occurred
        self.date_time_max = None   # Latest time the event could have occurred
        self.evidence_source = None # Source of the evidence
        self.type = None            # Type of the event, e.g., 'Google Search'
        self.description = None     # Human-readable description of the event
        self.category = None        # Category of the event for filtering
        self.plugin = None          # Plaso plugin that generates the event
        self.files = None           # File related to the event
        self.keys = {}              # Additional key-value pairs with extra information
        self.trigger = None         # Reasoning artefact that triggered the event
        self.supporting = {}        # List of reasoning artefacts supporting the event, five low level events before and after the event
        self.merged_id = []         # List of IDs of events that have been merged into this event
        self.date_time_iso = None   # ISO 8601 formatted date time

    def add_time(self, date_time: str):
        # Sets the time for the event, adjusting min and max if necessary
        self.date_time_min = date_time
        self.date_time_max = date_time

    def set_keys(self, key: Any, value: Any):
        # Adds additional information to the event
        self.keys[key] = value
    
    def merge(self, event_id: int):
        # Adds an event ID to the list of merged events
        self.merged_id.append(event_id)


class ReasoningArtefact:
    """Reasoning artefact class"""
    def __init__(self):
        self.id = None              # Unique identifier for the reasoning artefact
        self.description = None     # Human-readable description of the reasoning artefact
        self.test_event = None      # The event that triggered the reasoning artefact
        self.provenance = None      # Provenance details for traceability
        self.keys = {}              # Additional key-value pairs with extra information
        self.references = None      # Reference to external sources

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