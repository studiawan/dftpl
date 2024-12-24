import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.DefaultBrowser import FindDefaultBrowser


@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:34:47.890403+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path = r"NTFS:\Users\User\NTUSER.DAT"
    event1.evidence = r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice] Hash: [REG_SZ] 2F2Buyu+SaM= ProgId: [REG_SZ] MSEdgeHTM"
    event1.plugin = "REG-Registry Key-winreg/winreg_default"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T07:45:39.210988+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice] Hash: [REG_SZ] 2F2Buyu+SaM= ProgId: [REG_SZ] MSEdgeHTM",
                      "winreg/winreg_default",
                      r"NTFS:\Users\User\NTUSER.DAT",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindDefaultBrowser(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindDefaultBrowser(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Default Browser"
    assert high_timeline.events[0].description == "Default browser's ProgId is 'MSEdgeHTM'"
    assert high_timeline.events[0].category == "System"
    assert high_timeline.events[0].plugin == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[0].keys["Hash"] == "2F2Buyu+SaM="
    assert high_timeline.events[0].keys["ProgId"] == "MSEdgeHTM"
    assert high_timeline.events[0].files == r"NTFS:\Users\User\NTUSER.DAT"
    assert high_timeline.events[0].supporting == {
        'before': [],
        'after': [],
    }

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Default browser's ProgId found in registry 'HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' with value 'MSEdgeHTM'",
        'test_event': {
            'type': low_timeline.events[0].type,
            'evidence': r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://forensafe.com/blogs/Windows-Default-Browser.html',
        'keys': {},
    }
