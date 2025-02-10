import re
from datetime import datetime
from typing import List
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.reader.CSVReader import CSVReader
from dftpl.rules.Rule import Rule


num_supporting_events = 5

class LowLevelTimeline:
    def __init__(self):
        """Initializes the LowLevelTimeline object"""
        self.events: List[LowLevelEvent] = []  # List to store all low-level events
    
    def create_timeline(self, reader: CSVReader) -> list:
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
            if index > 0:   # Skip the first row, it is the CSV header
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
    
    def add_event(self, event: LowLevelEvent):
        """Adds a low-level event to the timeline"""
        self.events.append(event)

    def find_matching_events_in_id_range(self, start_id: int, end_id: int, test_event: LowLevelEvent) -> list:
        """Finds matching events in a given range of IDs"""
        matching_events = []
        for event in self.events[start_id:end_id]:
            if self.match(event, test_event):
                matching_events.append(event)
        
        return matching_events

    def find_matching_events_in_id_range_with_rule(
        self, start_id: int, end_id: int, rule: Rule
    ) -> List[LowLevelEvent]:
        """Find all events that match the rule's keywords"""
        matching_events = []

        # Determine matching behavior based on modifiers
        use_regex = "re" in rule.detection.modifiers
        require_all = "all" in rule.detection.modifiers

        for event in self.timeline.events[start_id:end_id]:
            event_text = f"{event.type} {event.evidence} {event.plugin}"

            matches = []

            # Check each keyword against the event text
            for keyword in self.rule.detection.keywords:
                match = self._check_keyword_match(event_text, keyword, use_regex)
                matches.append(match)

            should_include = False
            if require_all:
                should_include = all(matches)
            else:
                should_include = any(matches)

            if should_include:
                print(matches)
                matching_events.append(event)

        return matching_events

    def _apply_regex_matching(self, pattern: str, text: str) -> bool:
        """ "Apply regex pattern matching"""
        try:
            return bool(re.search(pattern, text))
        except re.error as e:
            print(f"Invalid regex atter `{pattern}`: {str(e)}")
            return False

    def _check_keyword_match(
        self, event_text: str, keyword: str, use_regex: bool
    ) -> bool:
        """Check if a keyword matches the event text"""
        if use_regex:
            return self._apply_regex_matching(keyword, event_text)
        return keyword in event_text

    def match(self, event: LowLevelEvent, test_event: LowLevelEvent) -> bool:
        """Tries to match a test event with the current event and returns true if they match"""
        if not re.search(test_event.type, event.type):
            return None
        if not re.search(test_event.evidence, event.evidence):
            return None
        else:
            return True
        
    def get_supporting_events(self, event_id: int, num_before: int=num_supporting_events, num_after: int=num_supporting_events) -> dict:
        """Returns a list of events before and after the event"""
        supporting_events = {}
        before_events = []
        after_events = []

        # Get the events before and after the event
        if event_id == 0:
            num_before = 0

        for event in self.events[event_id-num_before-1:event_id-1]:
            before_events.append(event.to_dict())

        for event in self.events[event_id:event_id+num_after]:
            after_events.append(event.to_dict())
        
        # Add the events to the dictionary
        supporting_events['before'] = before_events
        supporting_events['after'] = after_events
        
        return supporting_events
    
    def get_list_of_matches_in_sub_timeline(self, test_event: LowLevelEvent, start_time: datetime, end_time: datetime) -> list:
        """Returns a list of events that match the test events in a given time frame"""
        results = []
        for event in self.events:  
            if datetime.fromisoformat(event.date_time_min) >= start_time and datetime.fromisoformat(event.date_time_min) <= end_time:
                if self.match(event, test_event):
                    results.append(event)
        
        return results

    def find_matching_events_with_test_event_dict(self, test_event_dict: dict, start_id: int, end_id: int) -> list:
        """Finds matching events with a test event dictionary"""
        matching_events = []
        for test_event in test_event_dict.values():
            matching_event = self.find_matching_events_in_id_range(start_id, end_id, test_event)

            if matching_event:
                matching_events.extend(matching_event)
            else:
                return None
        
        return matching_events

