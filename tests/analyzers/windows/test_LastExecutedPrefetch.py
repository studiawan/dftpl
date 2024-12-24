import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.LastExecutedPrefetch import FindLastExecutedPrefetch


@pytest.fixture
def low_timeline():
    # create a test event to match against

    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-08-29T08:00:19.339633+00:00"
    event1.date_time_max = None
    event1.type = "Previous Last Time Executed-LOG"
    event1.path = r"NTFS:\Windows\Prefetch\CHROMESETUP.EXE-5C9EC5EC.pf"
    event1.evidence = r"Prefetch [CHROMESETUP.EXE] was executed - run count 4 path hints: \USERS\USER\DOWNLOADS\CHROMESETUP.EXE hash: 0x5C9EC5EC volume: 1 [serial number: 0xB63032B5  device path: \VOLUME{01da906b2f897af6-b63032b5}]"
    event1.plugin = "LOG-WinPrefetch-prefetch"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T08:00:19.339633+00:00",
                      "Previous Last Time Executed",
                      "LOG",
                      "WinPrefetch",
                      r"Prefetch [CHROMESETUP.EXE] was executed - run count 4 path hints: \USERS\USER\DOWNLOADS\CHROMESETUP.EXE hash: 0x5C9EC5EC volume: 1 [serial number: 0xB63032B5  device path: \VOLUME{01da906b2f897af6-b63032b5}]",
                      "prefetch",
                      r"NTFS:\Windows\Prefetch\CHROMESETUP.EXE-5C9EC5EC.pf",
                      "-"]
    }
    event1.keys = None

    # Event 2 is a composite of the events below
    # To give a case of multiple app path and volumes
    # 2012-03-15T21:17:39.807997+00:00,Last Time Executed,LOG,WinPrefetch,Prefetch [WUAUCLT.EXE] was executed - run count 25 path hints: \WINDOWS\SYSTEM32\WUAUCLT.EXE hash: 0x830BCC14 volume: 1 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUME1]  volume: 2 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY2]  volume: 3 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY4]  volume: 4 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY7]  volume: 5 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY8],prefetch,OS:/data/winprefetch/WUAUCLT.EXE-830BCC14.pf,-
    # 2024-08-29T08:00:21.768686+00:00,Last Time Executed,LOG,WinPrefetch,Prefetch [UPDATER.EXE] was executed - run count 2 path hints: \WINDOWS\SYSTEMTEMP\GOOGLE1704_269451707\BIN\UPDATER.EXE; \PROGRAM FILES (X86)\GOOGLE\GOOGLEUPDATER\129.0.6651.0\UPDATER.EXE hash: 0x395865E2 volume: 1 [serial number: 0xB63032B5  device path: \VOLUME{01da906b2f897af6-b63032b5}],prefetch,NTFS:\Windows\Prefetch\UPDATER.EXE-395865E2.pf,-
    event2 = LowLevelEvent()
    event2.id = 1
    event2.date_time_min = "2024-08-29T08:00:21.768686+00:00"
    event2.date_time_max = None
    event2.type = "Last Time Executed-LOG"
    event2.path = r"NTFS:\Windows\Prefetch\UPDATER.EXE-395865E2.pf"
    event2.evidence = r"Prefetch [UPDATER.EXE] was executed - run count 2 path hints: \WINDOWS\SYSTEMTEMP\GOOGLE1704_269451707\BIN\UPDATER.EXE; \PROGRAM FILES (X86)\GOOGLE\GOOGLEUPDATER\129.0.6651.0\UPDATER.EXE hash: 0x395865E2 volume: 1 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUME1]  volume: 2 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY2]  volume: 3 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY4]  volume: 4 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY7]  volume: 5 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY8]"
    event2.plugin = "LOG-WinPrefetch-prefetch"
    event2.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T08:00:21.768686+00:00",
                      "Last Time Executed",
                      "LOG",
                      "WinPrefetch",
                      r"Prefetch [UPDATER.EXE] was executed - run count 2 path hints: \WINDOWS\SYSTEMTEMP\GOOGLE1704_269451707\BIN\UPDATER.EXE; \PROGRAM FILES (X86)\GOOGLE\GOOGLEUPDATER\129.0.6651.0\UPDATER.EXE hash: 0x395865E2 volume: 1 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUME1]  volume: 2 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY2]  volume: 3 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY4]  volume: 4 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY7]  volume: 5 [serial number: 0xAC036525  device path: \DEVICE\HARDDISKVOLUMESHADOWCOPY8]",
                      "prefetch",
                      r"NTFS:\Windows\Prefetch\UPDATER.EXE-395865E2.pf",
                      "-"]
    }
    event2.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)

    return timeline

def test_FindLastExecutedPrefetch(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindLastExecutedPrefetch(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[0].type == "Previous Last Time Executed (Prefetch)"
    assert high_timeline.events[0].description == "Previous Last Time Executed of 'CHROMESETUP.EXE' (hash: 0x5C9EC5EC)"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].plugin == "LOG-WinPrefetch-prefetch"
    assert high_timeline.events[0].keys["App Name"] == "CHROMESETUP.EXE"
    assert high_timeline.events[0].keys["Run Count"] == "4"
    assert high_timeline.events[0].keys["File Hash"] == "0x5C9EC5EC"
    assert high_timeline.events[0].keys["App Path 1"] == r"\USERS\USER\DOWNLOADS\CHROMESETUP.EXE"
    assert high_timeline.events[0].keys["Volume 1 Serial Num"] == "0xB63032B5"
    assert high_timeline.events[0].keys["Volume 1 Device Path"] == "\VOLUME{01da906b2f897af6-b63032b5}"
    assert high_timeline.events[0].files == r"NTFS:\Windows\Prefetch\CHROMESETUP.EXE-5C9EC5EC.pf"
    assert len(high_timeline.events[0].supporting['after']) == 1

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': f"Previous Last Time Executed of 'CHROMESETUP.EXE' (hash: 0x5C9EC5EC) found in prefetch file 'NTFS:\Windows\Prefetch\CHROMESETUP.EXE-5C9EC5EC.pf'",
        'test_event': {
            'type': r"^(?:Previous )?Last Time Executed-LOG$",
            'evidence': r'^Prefetch \[.+\] was executed'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/',
        'keys': {},
    }

    assert high_timeline.events[1].type == "Last Time Executed (Prefetch)"
    assert high_timeline.events[1].description == "Last Time Executed of 'UPDATER.EXE' (hash: 0x395865E2)"
    assert high_timeline.events[1].category == "Windows"
    assert high_timeline.events[1].plugin == "LOG-WinPrefetch-prefetch"
    assert high_timeline.events[1].keys["App Name"] == "UPDATER.EXE"
    assert high_timeline.events[1].keys["Run Count"] == "2"
    assert high_timeline.events[1].keys["File Hash"] == "0x395865E2"
    assert high_timeline.events[1].keys["App Path 1"] == r"\WINDOWS\SYSTEMTEMP\GOOGLE1704_269451707\BIN\UPDATER.EXE"
    assert high_timeline.events[1].keys["App Path 2"] == r"\PROGRAM FILES (X86)\GOOGLE\GOOGLEUPDATER\129.0.6651.0\UPDATER.EXE"
    assert high_timeline.events[1].keys["Volume 1 Serial Num"] == "0xAC036525"
    assert high_timeline.events[1].keys["Volume 1 Device Path"] == "\DEVICE\HARDDISKVOLUME1"
    assert high_timeline.events[1].keys["Volume 2 Serial Num"] == "0xAC036525"
    assert high_timeline.events[1].keys["Volume 2 Device Path"] == "\DEVICE\HARDDISKVOLUMESHADOWCOPY2"
    assert high_timeline.events[1].keys["Volume 3 Serial Num"] == "0xAC036525"
    assert high_timeline.events[1].keys["Volume 3 Device Path"] == "\DEVICE\HARDDISKVOLUMESHADOWCOPY4"
    assert high_timeline.events[1].keys["Volume 4 Serial Num"] == "0xAC036525"
    assert high_timeline.events[1].keys["Volume 4 Device Path"] == "\DEVICE\HARDDISKVOLUMESHADOWCOPY7"
    assert high_timeline.events[1].keys["Volume 5 Serial Num"] == "0xAC036525"
    assert high_timeline.events[1].keys["Volume 5 Device Path"] == "\DEVICE\HARDDISKVOLUMESHADOWCOPY8"
    assert high_timeline.events[1].files == r"NTFS:\Windows\Prefetch\UPDATER.EXE-395865E2.pf"
    assert len(high_timeline.events[1].supporting['after']) == 1

    assert high_timeline.events[1].trigger == {
        'id': low_timeline.events[1].id,
        'description': f"Last Time Executed of 'UPDATER.EXE' (hash: 0x395865E2) found in prefetch file 'NTFS:\Windows\Prefetch\\UPDATER.EXE-395865E2.pf'",
        'test_event': {
            'type': r"^(?:Previous )?Last Time Executed-LOG$",
            'evidence': r'^Prefetch \[.+\] was executed'
        },
        'provenance': low_timeline.events[1].provenance,
        'references': 'https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/',
        'keys': {},
    }



