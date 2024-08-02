import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.TimezoneSettings import FindTimezoneSettings


@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-07-12T05:52:00.813418+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path = r"NTFS:\Windows\System32\config\SYSTEM"
    event1.evidence = "r[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\TimeZoneInformation] ActiveTimeBias: -420 Bias: -420 DaylightBias: 0 DaylightName: @tzres.dll -561 DynamicDaylightTimeDisabled: 0 StandardBias: 0 StandardName: @tzres.dll -562 TimeZoneKeyName: SE Asia Standard Time"
    event1.plugin = "REG-Registry Key-winreg/windows_timezone"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-07-12T05:52:00.813418+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      r"[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\TimeZoneInformation] ActiveTimeBias: -420 Bias: -420 DaylightBias: 0 DaylightName: @tzres.dll -561 DynamicDaylightTimeDisabled: 0 StandardBias: 0 StandardName: @tzres.dll -562 TimeZoneKeyName: SE Asia Standard Time",
                      "winreg/windows_timezone",
                      r"NTFS:\Windows\System32\config\SYSTEM",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindTimezoneSettings(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindTimezoneSettings(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Timezone Settings Changed"
    assert high_timeline.events[0].description == "Timezone set to SE Asia Standard Time (UTC +7)"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].device == "REG-Registry Key-winreg/windows_timezone"
    assert high_timeline.events[0].keys["ActiveTimeBias"] ==  "-420"
    assert high_timeline.events[0].keys["Bias"] ==  "-420"
    assert high_timeline.events[0].keys["DaylightBias"] ==  "0"
    assert high_timeline.events[0].keys["DaylightName"] ==  "@tzres.dll -561"
    assert high_timeline.events[0].keys["DynamicDaylightTimeDisabled"] ==  "0"
    assert high_timeline.events[0].keys["StandardBias"] ==  "0"
    assert high_timeline.events[0].keys["StandardName"] ==  "@tzres.dll -562"
    assert high_timeline.events[0].keys["TimeZoneKeyName"] ==  "SE Asia Standard Time"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\config\SYSTEM"
    assert high_timeline.events[0].supporting == {
        'before': [{
            'id': low_timeline.events[0].id,
            'date_time_min': low_timeline.events[0].date_time_min,
            'date_time_max': low_timeline.events[0].date_time_max,
            'type': low_timeline.events[0].type,
            'path': low_timeline.events[0].path,
            'evidence': low_timeline.events[0].evidence,
            'provenance': low_timeline.events[0].provenance,
            'plugin': low_timeline.events[0].plugin,
            'keys': low_timeline.events[0].keys
        }],
        'after': [],
    }

    assert high_timeline.events[0].trigger.id == 1
    assert high_timeline.events[0].trigger.description == r"Timezone information found in 2024-07-12T05:52:00.813418+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\TimeZoneInformation] ActiveTimeBias: -420 Bias: -420 DaylightBias: 0 DaylightName: @tzres.dll -561 DynamicDaylightTimeDisabled: 0 StandardBias: 0 StandardName: @tzres.dll -562 TimeZoneKeyName: SE Asia Standard Time,winreg/windows_timezone,NTFS:\Windows\System32\config\SYSTEM,-"