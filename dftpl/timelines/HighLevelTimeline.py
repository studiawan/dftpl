
class HighLevelTimeline:
    def __init__(self):
        self.events = []
    
    def add_event(self, event):
        self.events.append(event)
    
    def get_indexes_of_events_between_datetimes(self, start_datetime, end_datetime):
        indexes = []
        for i, event in enumerate(self.events):
            if event.date_time_min >= start_datetime and event.date_time_max <= end_datetime:
                indexes.append(i)
        return indexes
    
    def intersect_with(self, index, indexes):
        merged = False
        for i in indexes:
            if self.exact_match(self.events[index], self.events[i]):
                self.events[index].merge(self.events[i].id)
                merged = True
        
        return merged

    def exact_match(self, event, another_event):
        """Tries to match a test event with the current event and returns true if they match exactly. We do not check id, date_time_min, date_time_max, trigger, supporting, merged_id"""
        if event.evidence_source != another_event.evidence_source:
            return None
        if event.type != another_event.type:
            return None
        if event.description != another_event.description:
            return None
        if event.category != another_event.category:
            return None
        if event.device != another_event.device:
            return None
        if event.files != another_event.files:
            return None
        if event.keys != another_event.keys:
            return None
        
        return True
        
        