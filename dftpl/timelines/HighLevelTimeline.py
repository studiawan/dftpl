from datetime import datetime
from dftpl.events.HighLevelEvent import HighLevelEvent


class HighLevelTimeline:
    """A class to represent a high-level timeline of events"""
    
    def __init__(self):
        """Initialize the HighLevelTimeline object"""
        self.events = []
    
    def add_event(self, event: HighLevelEvent):
        """Add a HighLevelEvent object to the HighLevelTimeline object"""
        self.events.append(event)
    
    def add_events(self, events: list[HighLevelEvent]):
        """Add a list of HighLevelEvent objects to the HighLevelTimeline object"""
        self.events.extend(events)

    def get_indexes_of_events_between_datetimes(self, start_datetime: datetime, end_datetime: datetime) -> list[int]:
        """Get the indexes of events that fall between the start and end datetimes"""

        # Initialize an empty list to store the indexes of events 
        indexes = []

        # Iterate through the events and check if the date_time_min and date_time_max fall between the start and end datetimes
        for i, event in enumerate(self.events):
            # Compare the date_time_min and date_time_max with the start and end datetimes
            if datetime.fromisoformat(event.date_time_min) >= start_datetime and datetime.fromisoformat(event.date_time_max) <= end_datetime:
                indexes.append(i)
        
        return indexes
    
    def intersect_with(self, index: int, indexes: list[int]) -> bool:
        """Check if the event at the given index intersects with any of the events in the list of indexes"""
        
        # Initialize a flag to indicate if the events have been merged
        merged = False

        for i in indexes:
            # Check if the events match exactly
            if self.exact_match(self.events[index], self.events[i]):
                print("Merging events: ", self.events[index].evidence_source, " and ", self.events[i].evidence_source)
                self.events[index].merge(self.events[i].id)
                merged = True
        
        return merged

    def exact_match(self, event: HighLevelEvent, another_event: HighLevelEvent) -> bool:
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


class MergeHighLevelTimeline:
    """A class to merge multiple HighLevelTimeline objects into a single HighLevelTimeline object"""

    def __init__(self, high_timelines: HighLevelTimeline):
        """Initialize the MergeHighLevelTimeline object with a list of HighLevelTimeline objects"""
        self.high_timelines = high_timelines
    
    def merge(self) -> HighLevelTimeline:
        """Merge the HighLevelTimeline objects into a single HighLevelTimeline object"""

        # Initialize an empty list to combine all lists
        merged_timeline = []
        
        # Use extend method in a for loop to combine lists
        for high_timeline in self.high_timelines:
            merged_timeline.extend(high_timeline.events)

        # Convert date_time_min to datetime objects for sorting
        for event in merged_timeline:
            event.date_time_iso = datetime.fromisoformat(event.date_time_min)
        
        # Sort the combined list by the date_time_obj key
        merged_timeline.sort(key=lambda x: x.date_time_iso)
        
        # Create a new HighLevelTimeline object to store the merged timeline
        merged_high_timeline = HighLevelTimeline()
        merged_high_timeline.add_events(merged_timeline)

        return merged_high_timeline