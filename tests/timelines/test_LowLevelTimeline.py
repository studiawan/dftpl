import pytest
import csv
from dftpl.reader.CSVReader import CSVReader
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent


@pytest.fixture
def csv_reader():
    csv.field_size_limit(10000000) 
    file_path = 'test_data/13-sample.csv'
    
    return CSVReader(file_path)

def test_create_timeline(csv_reader):
    timeline = LowLevelTimeline()
    events = timeline.create_timeline(csv_reader)
    
    assert len(events) == 4

def test_add_event():
    timeline = LowLevelTimeline()
    event = LowLevelEvent()
    timeline.add_event(event)
    
    assert len(timeline.events) == 1

def test_find_matching_events_in_id_range():
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:43:28.536120+00:00" 
    event1.date_time_max = None
    event1.type = "Metadata Modification Time-FILE"
    event1.path = r"NTFS:\$Extend\$UsnJrnl:$J"
    event1.evidence = "install.tmp File reference: 134110-12 Parent file reference: 244418-2 Update source:  Update reason: USN_REASON_FILE_DELETE  USN_REASON_CLOSE"
    event1.plugin = "FILE-NTFS USN change-usnjrnl"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:43:28.536120+00:00",
                      "Metadata Modification Time",
                      "FILE",
                      "NTFS USN change",
                      "install.tmp File reference: 134110-12 Parent file reference: 244418-2 Update source:  Update reason: USN_REASON_FILE_DELETE  USN_REASON_CLOSE",
                      "usnjrnl",
                      r"NTFS:\$Extend\$UsnJrnl:$J",
                      "-"]
    }
    event1.keys = None

    event2 = LowLevelEvent()
    event2.id = 3
    event2.date_time_min = "2023-12-26 00:45:45.817000+00:00"
    event2.date_time_max = None
    event2.type = "Last Visited Time-WEBHIST"
    event2.path = r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite"
    event2.evidence = "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK"
    event2.plugin = "WEBHIST-Firefox History-sqlite/firefox_history"
    event2.provenance = {
        'line_number': 3,
        'raw_entry': ["2023-12-26 00:45:45.817000+00:00",
                      "Last Visited Time",
                      "WEBHIST",
                      "Firefox History",
                      "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK",
                      "sqlite/firefox_history",
                      r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite",
                      "-"]
    }
    event2.keys = None
    
    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)

    # Create test event
    test_event = LowLevelEvent()
    test_event.type = "Last Visited Time-WEBHIST"
    test_event.evidence = r'https?://(.+\.)(google)\.(?:com|co\.uk|fr)'

    # Test matching events
    matching_events = timeline.find_matching_events_in_id_range(0, 2, test_event)
    
    assert len(matching_events) == 1
    assert matching_events[0] == event2
    