import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.LastExecutedPCA import FindLastExecutedPCA


@pytest.fixture
def low_timeline():
    # create a test event to match against

    # Test event for PcaGeneralDb0.txt artifact (from plaso's test_data)
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2022-11-15T00:00:17.499000+00:00"
    event1.date_time_max = None
    event1.type = "Last Time Executed-LOG"
    event1.path = r"OS:/data/file/PcaGeneralDb0.txt"
    event1.evidence = r"[\program files\git\mingw64\bin\git.exe] was executed -  Description: git Version: 2.33.0.windows.2 Vendor: the git development community Exit code: Abnormal process exit with code 0x1"
    event1.plugin = "LOG-Program Compatibility Assistant (PCA) Log-winpca_db0"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2022-11-15T00:00:17.499000+00:00",
                      "Last Time Executed",
                      "LOG",
                      "Program Compatibility Assistant (PCA) Log",
                      r"[\program files\git\mingw64\bin\git.exe] was executed -  Description: git Version: 2.33.0.windows.2 Vendor: the git development community Exit code: Abnormal process exit with code 0x1",
                      "winpca_db0",
                      r"OS:/data/file/PcaGeneralDb0.txt",
                      "-"]
    }
    event1.keys = None

    # Test event for PcaAppLaunchDic.txt (from author's personal scenario result)
    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2024-08-29T08:00:19.327000+00:00"
    event2.date_time_max = None
    event2.type = "Last Time Executed-LOG"
    event2.path = r"NTFS:\Windows\appcompat\pca\PcaAppLaunchDic.txt"
    event2.evidence = r"[C:\Users\User\Downloads\ChromeSetup.exe] was executed - "
    event2.plugin = "LOG-Program Compatibility Assistant (PCA) Log-winpca_dic"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2024-08-29T08:00:19.327000+00:00",
                      "Last Time Executed",
                      "LOG",
                      "Program Compatibility Assistant (PCA) Log",
                      r"[C:\Users\User\Downloads\ChromeSetup.exe] was executed - ",
                      "winpca_dic",
                      r"NTFS:\Windows\appcompat\pca\PcaAppLaunchDic.txt",
                      "-"]
    }
    event2.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)

    return timeline

def test_FindLastExecutedPCA(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindLastExecutedPCA(low_timeline, start_id, end_id)

    # Test for 'winpca_db0' plugin
    assert len(high_timeline.events) == 2
    assert high_timeline.events[0].type == "Last Time Executed (PCA plugin 'winpca_db0')"
    assert high_timeline.events[0].description == r"Last Time Executed of '\program files\git\mingw64\bin\git.exe'"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].plugin == "LOG-Program Compatibility Assistant (PCA) Log-winpca_db0"
    assert high_timeline.events[0].keys["Path"] == r"\program files\git\mingw64\bin\git.exe"
    assert high_timeline.events[0].keys["Description"] == "git"
    assert high_timeline.events[0].keys["Version"] == r"2.33.0.windows.2"
    assert high_timeline.events[0].keys["Vendor"] == r"the git development community"
    assert high_timeline.events[0].keys["Exit Code"] == r"Abnormal process exit with code 0x1"
    assert high_timeline.events[0].files == r"OS:/data/file/PcaGeneralDb0.txt"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Last Time Executed of '\program files\git\mingw64\bin\git.exe' found in 'OS:/data/file/PcaGeneralDb0.txt'",
        'test_event': {
            'type': "Last Time Executed-LOG",
            'evidence': r'^\[.+\] was executed - '
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://artefacts.help/windows_pca.html',
        'keys': {},
    }

    # Test for 'winpca_dic' plugin
    assert high_timeline.events[1].type == "Last Time Executed (PCA plugin 'winpca_dic')"
    assert high_timeline.events[1].description == r"Last Time Executed of 'C:\Users\User\Downloads\ChromeSetup.exe'"
    assert high_timeline.events[1].category == "Windows"
    assert high_timeline.events[1].plugin == "LOG-Program Compatibility Assistant (PCA) Log-winpca_dic"
    assert high_timeline.events[1].keys["Path"] == r"C:\Users\User\Downloads\ChromeSetup.exe"
    assert high_timeline.events[1].files == r"NTFS:\Windows\appcompat\pca\PcaAppLaunchDic.txt"

    assert high_timeline.events[1].trigger == {
        'id': low_timeline.events[1].id,
        'description': r"Last Time Executed of 'C:\Users\User\Downloads\ChromeSetup.exe' found in 'NTFS:\Windows\appcompat\pca\PcaAppLaunchDic.txt'",
        'test_event': {
            'type': "Last Time Executed-LOG",
            'evidence': r'^\[.+\] was executed - '
        },
        'provenance': low_timeline.events[1].provenance,
        'references': 'https://artefacts.help/windows_pca.html',
        'keys': {},
    }



