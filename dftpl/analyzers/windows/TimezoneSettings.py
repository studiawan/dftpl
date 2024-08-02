# Clement : Authorship is copied from other files.
__author__ = ['Jony Patterson', 'Hudan Studiawan']

# For sys.exit()
import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "Timezone Settings Changed"
analyser_category = "Windows"

# TODO : Ask why 4 analyzers have the function below with the name "DontRun" (others use the name "Run").
"""
def DontRun(timeline, casepath, queue, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)
    TimezoneSettings(timeline, queue, start_id, end_id)
"""

# 2024-07-12T05:52:00.813418+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\TimeZoneInformation] ActiveTimeBias: -420 Bias: -420 DaylightBias: 0 DaylightName: @tzres.dll -561 DynamicDaylightTimeDisabled: 0 StandardBias: 0 StandardName: @tzres.dll -562 TimeZoneKeyName: SE Asia Standard Time,winreg/windows_timezone,NTFS:\Windows\System32\config\SYSTEM,-
def Run(low_timeline, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(low_timeline.events)
    return TimezoneSettings(low_timeline, start_id, end_id)

def TimezoneSettings(low_timeline, start_id, end_id):
    test_event = LowLevelEvent()
    test_event.evidence = r"\\Control\\TimeZoneInformation]"
    test_event.path = r"Windows\\System32\\config\\SYSTEM"
    # NEW : Add type checking so LowLevelTimeline.match won't fail
    test_event.type = "Content Modification Time-REG"

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)
    for each_low_event in trigger_matches:
        if each_low_event.match(test_event):
            if re.search(test_event.path, each_low_event.path):
                high_event = HighLevelEvent()
                # NEW : Add id
                high_event.id = each_low_event.id
                high_event.add_time(each_low_event.date_time_min)
                high_event.evidence_source = each_low_event.evidence
                high_event.type = "Timezone Settings Changed"

                # NEW : Since low level events doesn't have keys, manually parse low level evidence for the keys.
                # Regex used to capture each keys : (\w+)(?:: )(.+?)(?=(?:(?:\w+)(?:: ))|$)
                # (\w+) = 1st capturing group. Captures key name
                # (?:: ) = Skip over ": "
                # (.+?) = 2nd capturing group. Captures key value. With positive lookahead, will capture until character before the next key name, usually a single space " ".
                # (?=(?:(?:\w+)(?:: ))|$) = Positive lookahead to check if there's another keyname after 2nd capturing group or end of string.

                # Trying out annotation for loop variables.
                key_name: str
                key_value: str
                for key_name, key_value in re.findall(r'(\w+)(?:: )(.+?)(?=(?:(?:\w+)(?:: ))|$)', each_low_event.evidence):
                    high_event.set_keys(key_name, key_value.rstrip())

                # NEW : Use default key names from log instead of "Timezone"
                    high_event.description = f"Timezone set to {high_event.keys["TimeZoneKeyName"]} (UTC {-1 * (high_event.keys["ActiveTimeBias"] / 60)})"
                high_event.category = analyser_category
                high_event.device = each_low_event.plugin
                # NEW : File value
                high_event.files = each_low_event.path
                # NEW : ActiveTimeBias value shouldn't need to be processed again, see below.
                # NEW : Get surrounding events
                high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

                # Create a reasoning artefact
                reasoning = ReasoningArtefact()
                reasoning.id = each_low_event.id
                # NEW : Regex to extract registry path information
                # Extracts path between first set of angle brackets.
                reasoning.description = f"Timezone information found in {','.join(each_low_event.provenance['raw_entry'])}"
                reasoning.test_event = test_event
                # Add the reasoning artefact to the high level event
                high_event.trigger = reasoning
                # Add the high level event to the high level timeline
                high_timeline.add_event(high_event)

    return high_timeline


# NOTE : ActiveTimeBias is the timezone offset from utc in minutes. UTC can be calculated following this formula :
#           UTC = Local Time + ActiveTimeBias
#           Ex : If local time is UTC+7, then ActiveTimeBias should be -420 (-7 * 60).
# Therefore, these functions should be redudant now since in plaso's output, it's an integer, not raw hex.

# Currently, these functions are unused.
# TODO : Ask what the functions below are used for + output format for ActiveTimeZone when original research was done.
# Source : https://www.digital-detective.net/time-zone-identification/ (Accessed : 21:02, 24th of July 2024)
def GetActiveTimeBias(bias_data):
    """Converts data into ActiveTimeBias"""
    max_number = int.from_bytes(b'\xff\xff\xff\xff',byteorder='little') + 1
    half_max_value = (max_number / 2) - 1
    bias_integer = GetBiasInteger(bias_data)

    if bias_integer > half_max_value:
        bias = bias_integer - max_number
        return bias
    else:
        return bias_integer


def GetBiasInteger(bias_data):
    """returns bias that has been reversed and converted to an integer"""
    # NEW : Shift index 2 to the right. New code retrieves hex value with "0x" prefix.
    bias_reversed = bias_data[8:10] + bias_data[6:8] + bias_data[4:6] + bias_data[2:4]
    bias_int = int(bias_reversed, 16)
    return bias_int

class TimezoneConversionException(Exception):
    """Exception in Registry Parser"""
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

