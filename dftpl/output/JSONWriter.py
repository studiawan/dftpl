import json
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


class JSONWriter:
    def __init__(self, timeline: HighLevelTimeline, json_path: str):
        """Initializes the JSONWriter class"""
        self.timeline = timeline.events
        self.json_path = json_path

    def to_dict(self) -> dict:
        """Converts the timeline (list) to a dictionary"""
        timeline_dict = {}
        for index, event in enumerate(self.timeline):
            timeline_dict[index] = {
                'id': event.id,
                'date_time_min': event.date_time_min,
                'date_time_max': event.date_time_max,
                'evidence_source': event.evidence_source,
                'type': event.type,
                'description': event.description,
                'category': event.category,
                'plugin': event.plugin,
                'files': event.files,
                'keys': event.keys,
                'supporting': event.supporting,
                'trigger': event.trigger
            }
        
        return timeline_dict

    def write(self):
        """Writes the timeline to a JSON file"""
        timeline_dict = self.to_dict()
        
        with open(self.json_path, 'w') as file:
            json.dump(timeline_dict, file, indent=4)
        