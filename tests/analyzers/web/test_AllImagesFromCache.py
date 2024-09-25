import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.web.AllImagesFromCache import CachedImages

# grep -i image 0.csv| grep WEBHIST
# 2023-12-26 00:38:54.825904+00:00,Synchronization Time,WEBHIST,MSIE WebCache container record,URL: https://assets.msn.com/weathermapdata/1/static/weather/Icons/KRYFGAA=/Condition/AAehYNC.png Access count: 1 Synchronization count: 0 Filename: AAehYNC[1].png Cached file size: 2789 Request headers: [] Response headers: [HTTP/1.1 200 OK; Content-Type: image/png; ETag: 0x8DBE671211AE1FF; x-ms-request-id: 61d1ce72-601e-009b-21e5-1aa853000000; x-ms-version: 2009-09-19; x-ms-lease-status: unlocked; x-ms-blob-type: BlockBlob; Access-Control-Expose-Headers: x-ms-request-id Server x-ms-version Content-Type Last-Modified ETag x-ms-lease-status x-ms-blob-type Content-Length Date Transfer-Encoding; Access-Control-Allow-Origin: *; Akamai-Request-BC: [a=23.205.70.102 b=505153526 c=g n=ID_JI_SURABAYA o=7713]; Server-Timing: clientrtt; dur=6  clienttt; dur=0  origin; dur=0   cdntime; dur=0; Akamai-Cache-Status: Hit from child; Akamai-Server-IP: 23.205.70.102; Akamai-Request-ID: 1e1c07f6; Timing-Allow-Origin: *; Akamai-GRN: 0.6646cd17.1703551134.1e1c07f6; Vary: Origin; Content-Length: 2789] Entry identifier: 16 Container identifier: 2 Cache identifier: 0,esedb/msie_webcache,NTFS:\Users\User\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat,-

@pytest.fixture
def low_timeline():
    # Create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:38:54.825904+00:00"
    event1.date_time_max = None
    event1.type = "WEBHIST"
    event1.path = r"NTFS:\Users\User\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"
    event1.evidence = r"URL: https://assets.msn.com/weathermapdata/1/static/weather/Icons/KRYFGAA=/Condition/AAehYNC.png Access count: 1 Synchronization count: 0 Filename: AAehYNC[1].png Cached file size: 2789 Request headers: [] Response headers: [HTTP/1.1 200 OK; Content-Type: image/png; ETag: 0x8DBE671211AE1FF; x-ms-request-id: 61d1ce72-601e-009b-21e5-1aa853000000; x-ms-version: 2009-09-19; x-ms-lease-status: unlocked; x-ms-blob-type: BlockBlob; Access-Control-Expose-Headers: x-ms-request-id Server x-ms-version Content-Type Last-Modified ETag x-ms-lease-status x-ms-blob-type Content-Length Date Transfer-Encoding; Access-Control-Allow-Origin: *; Akamai-Request-BC: [a=23.205.70.102 b=505153526 c=g n=ID_JI_SURABAYA o=7713]; Server-Timing: clientrtt; dur=6  clienttt; dur=0  origin; dur=0   cdntime; dur=0; Akamai-Cache-Status: Hit from child; Akamai-Server-IP: 23.205.70.102; Akamai-Request-ID: 1e1c07f6; Timing-Allow-Origin: *; Akamai-GRN: 0.6646cd17.1703551134.1e1c07f6; Vary: Origin; Content-Length: 2789] Entry identifier: 16 Container identifier: 2 Cache identifier: 0"
    event1.plugin = "WEBHIST-MSIE WebCache container record-esedb/msie_webcache"
    event1.provenance = {
        'line_number': 3,
        'raw_entry': ["2023-12-26 00:38:54.825904+00:00",
                      "Synchronization Time",
                      "WEBHIST",
                      "MSIE WebCache container record",
                      r"URL: https://assets.msn.com/weathermapdata/1/static/weather/Icons/KRYFGAA=/Condition/AAehYNC.png Access count: 1 Synchronization count: 0 Filename: AAehYNC[1].png Cached file size: 2789 Request headers: [] Response headers: [HTTP/1.1 200 OK; Content-Type: image/png; ETag: 0x8DBE671211AE1FF; x-ms-request-id: 61d1ce72-601e-009b-21e5-1aa853000000; x-ms-version: 2009-09-19; x-ms-lease-status: unlocked; x-ms-blob-type: BlockBlob; Access-Control-Expose-Headers: x-ms-request-id Server x-ms-version Content-Type Last-Modified ETag x-ms-lease-status x-ms-blob-type Content-Length Date Transfer-Encoding; Access-Control-Allow-Origin: *; Akamai-Request-BC: [a=23.205.70.102 b=505153526 c=g n=ID_JI_SURABAYA o=7713]; Server-Timing: clientrtt; dur=6  clienttt; dur=0  origin; dur=0   cdntime; dur=0; Akamai-Cache-Status: Hit from child; Akamai-Server-IP: 23.205.70.102; Akamai-Request-ID: 1e1c07f6; Timing-Allow-Origin: *; Akamai-GRN: 0.6646cd17.1703551134.1e1c07f6; Vary: Origin; Content-Length: 2789] Entry identifier: 16 Container identifier: 2 Cache identifier: 0","esedb/msie_webcache",r"NTFS:\Users\User\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat",
                      "-"]
    }
    event1.keys = None

    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindAllImagesFromCache(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = CachedImages(low_timeline, start_id, end_id)
    
    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Image Cached"
    assert high_timeline.events[0].description == "Image cached: AAehYNC.png"
    assert high_timeline.events[0].category == "Web"
    assert high_timeline.events[0].plugin == "WEBHIST-MSIE WebCache container record-esedb/msie_webcache"
    assert high_timeline.events[0].keys["File Path"] == r"NTFS:\Users\User\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"
    assert high_timeline.events[0].keys["Content-Type"] == "image/png"
    assert high_timeline.events[0].keys["URL"] == "https://assets.msn.com/weathermapdata/1/static/weather/Icons/KRYFGAA=/Condition/AAehYNC.png"
    assert high_timeline.events[0].keys["Filename"] == "AAehYNC.png"
    assert high_timeline.events[0].trigger.test_event.evidence == r'https.*Content-Type:\s*image/'