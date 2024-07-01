import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.web.BingSearch import FindBingSearches

# 2023-12-26 00:35:54.337559+00:00,Creation Time,WEBHIST,Chrome Cache,Original URL: https://www.bing.com/search?form=&q=mozilla+firefox+download&form=QBLH&sp=-1&lq=0&pq=mozilla+firefox+download&sc=10-24,chrome_cache,NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index,-

@pytest.fixture
def low_timeline():
    # Create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:35:54.337559+00:00"
    event1.date_time_max = None
    event1.type = "WEBHIST"
    event1.path = r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index"
    event1.evidence = "Original URL: https://www.bing.com/search?form=&q=mozilla+firefox+download&form=QBLH&sp=-1&lq=0&pq=mozilla+firefox+download&sc=10-24"
    event1.plugin = "WEBHIST-Chrome Cache-chrome_cache"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:35:54.337559+00:00",
                      "Creation Time",
                      "WEBHIST",
                      "Chrome Cache",
                      "Original URL: https://www.bing.com/search?form=&q=mozilla+firefox+download&form=QBLH&sp=-1&lq=0&pq=mozilla+firefox+download&sc=10-24",
                      "chrome_cache",
                      r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index",
                      "-"]
    }
    event1.keys = None

    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_BingSearch(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindBingSearches(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].evidence_source == "Original URL: https://www.bing.com/search?form=&q=mozilla+firefox+download&form=QBLH&sp=-1&lq=0&pq=mozilla+firefox+download&sc=10-24"
    assert high_timeline.events[0].type == "Bing Search"
    assert high_timeline.events[0].description == "Bing Search for 'mozilla firefox download'"
    assert high_timeline.events[0].category == "Web"
    assert high_timeline.events[0].device == "WEBHIST-Chrome Cache-chrome_cache"
    assert high_timeline.events[0].keys["Browser"] == "WEBHIST-Chrome"
    assert high_timeline.events[0].keys["Path"] == r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index"
    assert high_timeline.events[0].keys["Search_Term"] == "mozilla firefox download"
