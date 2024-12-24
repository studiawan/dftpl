import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.RecycleBin import FindRecycleBin

@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-12-19T08:28:58.150000+00:00"
    event1.date_time_max = None
    event1.type = "Content Deletion Time-RECBIN"
    event1.path = r"OS:/data/$IMTP1O2.jpg"
    event1.evidence = r"C:\Users\Anonymous\Downloads\vod-2201104836-offset-12344-preview-260x147.jpg"
    event1.plugin = "RECBIN-Recycle Bin-recycle_bin"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-12-19T08:28:58.150000+00:00",
                      "Content Deletion Time",
                      "RECBIN",
                      "Recycle Bin",
                      r"C:\Users\Anonymous\Downloads\vod-2201104836-offset-12344-preview-260x147.jpg",
                      "recycle_bin",
                      r"OS:/data/$IMTP1O2.jpg",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_RecycleBin(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindRecycleBin(low_timeline, start_id, end_id)

    # High level timeline
    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Deletion Time (Recycle Bin)"
    assert high_timeline.events[0].description == r"Found deletion time for 'C:\Users\Anonymous\Downloads\vod-2201104836-offset-12344-preview-260x147.jpg'"
    assert high_timeline.events[0].category == "System"
    assert high_timeline.events[0].plugin == "RECBIN-Recycle Bin-recycle_bin"
    assert high_timeline.events[0].files == r"OS:/data/$IMTP1O2.jpg"
    assert high_timeline.events[0].supporting == {
        'before': [],
        'after': []
    }

    # Reasoning artefact
    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Deletion time found in 'OS:/data/$IMTP1O2.jpg'",
        'test_event': {
            'type': "Content Deletion Time-RECBIN",
            'evidence': r".*"
        },
        'provenance': low_timeline.events[0].provenance,
        'references': "https://www.magnetforensics.com/blog/artifact-profile-recycle-bin/",
        'keys': {},
    }
