import re


class LowLevelEvent:
    def __init__(self):
        self.id = None              # Unique identifier for the event
        self.date_time_min = None   # Earliest time the event could have occurred
        self.date_time_max = None   # Latest time the event could have occurred
        self.type = None            # The type of the event, e.g., 'File Created', 'URL Visit'
        self.path = None            # The object that the event relates to, e.g., a file path or URL
        self.provenance = None      # Provenance details for traceability
        self.evidence = None        # The evidence item that the event came from
        self.plugin = None          # The time extractor used to recover the event
        self.keys = {}              # Additional details about the event
    
    def match(self, test_event):
        """Tries to match a test event with the current event and returns true if they match"""
        if not re.search(test_event.type, self.type):
            return None
        if re.search(test_event.evidence, self.evidence) == None:
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
    
    

    