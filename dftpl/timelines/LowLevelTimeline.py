import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from datetime import datetime


num_supporting_events = 5

class LowLevelTimeline:
    def __init__(self):
        """Initializes the LowLevelTimeline object"""
        self.events = []  # List to store all low-level events
    
    def create_timeline(self, reader):
        """Creates a timeline of low-level events from a CSV file"""
        # map from plaso CSV columns to LowLevelEvent attributes
        # plaso CSV columns: 
        # [0] datetime,
        # [1] timestamp_desc,
        # [2] source,
        # [3] source_long,
        # [4] message,
        # [5] parser,
        # [6] display_name,
        # [7] tag

        for index, row in reader.read_csv():
            event = LowLevelEvent()
            event.id = index
            event.date_time_min = row[0]                    # [0] datetime
            event.date_time_max = None
            event.type = f"{row[1]}-{row[2]}"               # [1] timestamp_desc, [3] source_long
            event.path = row[6]                             # [6] display_name
            event.evidence = row[4]                         # [4] message
            event.plugin = f"{row[2]}-{row[3]}-{row[5]}"    # [2] source, [3] source_long, [5] parser
            event.provenance = {
                'line_number': index,
                'raw_entry': row
            }
            event.keys = None
            self.add_event(event)
        
        return self.events
    
    def add_event(self, event):
        """Adds a low-level event to the timeline"""
        self.events.append(event)

    def find_matching_events_in_id_range(self, start_id, end_id, test_event):
        matching_events = []
        for event in self.events[start_id:end_id]:
            if self.match(event, test_event):
                matching_events.append(event)
        
        return matching_events
    
    def match(self, event, test_event):
        """Tries to match a test event with the current event and returns true if they match"""
        if not re.search(test_event.type, event.type):
            return None
        if re.search(test_event.evidence, event.evidence) == None:
            return None
        else:
            return True
    
    def get_supporting_events(self, event_id, num_before=num_supporting_events, num_after=num_supporting_events):
        """Returns a list of events before and after the event"""
        supporting_events = {}
        before_events = []
        after_events = []

        # Get the events before and after the event
        if event_id == 0:
            num_before = 0

        for event in self.events[event_id-num_before:event_id]:
            before_events.append(event.to_dict())

        for event in self.events[event_id+1:event_id+num_after+1]:
            after_events.append(event.to_dict())
        
        # Add the events to the dictionary
        supporting_events['before'] = before_events
        supporting_events['after'] = after_events
        
        return supporting_events
    
    def get_list_of_matches_in_sub_timeline(self, test_event, start, end):
        """Returns a list of events that match the test events in a given time frame"""
        results = []
        for event in self.events:
            if datetime.fromisoformat(event.date_time_min) >= start and datetime.fromisoformat(event.date_time_min) <= end:
                if self.match(event, test_event):
                    results.append(event)
        
        return results

    def find_matching_events_with_test_event_dict(self, test_event_dict, start_id, end_id):
        """Finds matching events with a test event dictionary"""
        matching_events = []
        for test_event in test_event_dict.values():
            matching_event = self.find_matching_events_in_id_range(start_id, end_id, test_event)

            if matching_event:
                matching_events.extend(matching_event)
            else:
                return None
        
        return matching_events

