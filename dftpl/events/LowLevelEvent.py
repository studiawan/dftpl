import re
from typing import  Optional, Dict
from dftpl.events.BaseEvent import BaseEvent


class LowLevelEvent(BaseEvent):
    def __init__(self):
        super().__init__()
        self.path: Optional[str] = None           # The object that the event relates to, e.g., a file path or URL
        self.provenance: Optional[Dict] = None    # Provenance details for traceability
        self.evidence: Optional[str] = None       # The evidence item that the event came from
        self.plugin: Optional[str] = None         # The time extractor used to recover the event
    
    def match(self, test_event):
        """Tries to match a test event with the current event and returns true if they match"""
        if not re.search(test_event.type, self.type):
            return None
        if re.search(test_event.evidence, self.evidence) is None:
            return None
        else:
            return True
    
    def to_dict(self):
        """Converts the event to a dictionary"""
        event_dict = {
            'id': self.id,
            'date_time_min': self.date_time_min,
            'date_time_max': self.date_time_max,
            'type': self.type,
            'path': self.path,
            'evidence': self.evidence,
            'provenance': self.provenance,
            'plugin': self.plugin,
            'keys': self.keys
        }
        
        return event_dict
    
    

    