import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.web.WebVisits import FindWebVisits


@pytest.fixture
def low_timeline():
    # Create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:34:33.459996+00:00"
    event1.date_time_max = None
    event1.type = "WEBHIST"
    event1.path = r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index"
    event1.evidence = "Original URL: https://www.bing.com/bloomfilterfiles/ExpandedDomainsFilterGlobal.json"
    event1.plugin = "WEBHIST-Chrome Cache-chrome_cache"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:34:33.459996+00:00",
                      "Creation Time",
                      "WEBHIST",
                      "Chrome Cache",
                      "Original URL: https://www.bing.com/bloomfilterfiles/ExpandedDomainsFilterGlobal.json",
                      "chrome_cache",
                      r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index",
                      "-"]
    }
    event1.keys = None

    # 2023-12-26 00:35:04.505863+00:00,Creation Time,WEBHIST,Chrome Cache,Original URL: https://www.microsoft.com/en-us/edge/welcome?ep=255&form=MT00L8&es=59,chrome_cache,NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index,-
    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2023-12-26 00:35:04.505863+00:00"
    event2.date_time_max = None
    event2.type = "WEBHIST"
    event2.path = r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index"
    event2.evidence = "Original URL: https://www.microsoft.com/en-us/edge/welcome?ep=255&form=MT00L8&es=59"
    event2.plugin = "WEBHIST-Chrome Cache-chrome_cache"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2023-12-26 00:35:04.505863+00:00",
                      "Creation Time",
                      "WEBHIST",
                      "Chrome Cache",
                      "Original URL: https://www.microsoft.com/en-us/edge/welcome?ep=255&form=MT00L8&es=59",
                      "chrome_cache",
                      r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index",
                      "-"]
    }
    event2.keys = None

    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)

    return timeline

def test_FindWebVisits(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindWebVisits(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[0].type == "Web Visit"
    assert high_timeline.events[0].description == "Web Visit to 'www.bing.com'"
    assert high_timeline.events[0].category == "Web Overview"
    assert high_timeline.events[0].device == "WEBHIST-Chrome Cache-chrome_cache"
    assert high_timeline.events[0].keys["Browser"] == "WEBHIST-Chrome"
    assert high_timeline.events[0].keys["URL(2023-12-26 00:34:33.459996+00:00)"] == "https://www.bing.com/bloomfilterfiles/ExpandedDomainsFilterGlobal.json"