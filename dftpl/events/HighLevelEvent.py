class HighLevelEvent:
    def __init__(self):
        self.id = None              # Unique identifier for the event
        self.date_time_min = None   # Earliest time the event could have occurred
        self.date_time_max = None   # Latest time the event could have occurred
        self.evidence_source = None # Source of the evidence
        self.type = None            # Type of the event, e.g., 'Google Search'
        self.description = None     # Human-readable description of the event
        self.category = None        # Category of the event for filtering
        self.device = None          # Device related to the event
        self.files = None           # File related to the event
        self.keys = {}              # Additional key-value pairs with extra information
        self.trigger = None         # Reasoning artefact that triggered the event
        self.supporting = {}        # List of reasoning artefacts supporting the event, five low level events before and after the event

    def add_time(self, date_time):
        # Sets the time for the event, adjusting min and max if necessary
        self.date_time_min = date_time
        self.date_time_max = date_time

    def set_keys(self, key, value):
        # Adds additional information to the event
        self.keys[key] = value


class ReasoningArtefact:
    def __init__(self):
        self.id = None              # Unique identifier for the reasoning artefact
        self.description = None     # Human-readable description of the reasoning artefact
        self.test_event = None      # The event that triggered the reasoning artefact
        self.provenance = None      # Provenance details for traceability
        self.keys = {}              # Additional key-value pairs with extra information

    def set_keys(self, key, value):
        # Adds additional information to the reasoning artefact
        self.keys[key] = value