__author__ = 'Jony Patterson'

import PyDFT.Timelines.HighLevelTimeline
import PyDFT.Events.LowLevelEvent
import PyDFT.Events.HighLevelEvent
import PyDFT.Events.HighLevelReasoningArtefact
import PyDFT.Events.Event
import PyDFT.Utilities.TimeCore
import logging

description = "Timezone Settings"
analyser_category = "System"

def DontRun(timeline, casepath, queue, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)
    TimezoneSettings(timeline, queue, start_id, end_id)

def TimezoneSettings(low_timeline, queue, start_id, end_id):
    high_level_timeline = PyDFT.Timelines.HighLevelTimeline.high_level_timeline()

    test_event = PyDFT.Events.LowLevelEvent.low_level_event()
    test_event.path = "/Control/TimeZoneInformation$"
    test_event.dataprov_source = "Windows/System32/config/SYSTEM"

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    for each_event in trigger_matches:
        if each_event.match(test_event):
            high_event = PyDFT.Events.HighLevelEvent.high_level_event()
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "Timezone Settings Changed"
            high_event.description = "Timezone set to %s" % each_event.keys["TimeZoneKeyName"]
            high_event.set_keys("Timezone", each_event.keys["TimeZoneKeyName"])
            high_event.category = analyser_category
            high_event.device = each_event.evidence
            if "ActiveTimeBias" in each_event.keys:
                high_event.set_keys("ActiveTimeBias", GetActiveTimeBias(each_event.keys["ActiveTimeBias"]))
            reasoning = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "Timezone information found in %s" % each_event.path
            reasoning.test_event = test_event

            high_event.trigger = reasoning

            high_level_timeline.add_event(high_event)

    queue.put(high_level_timeline)

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
    bias_reversed = bias_data[6:8] + bias_data[4:6] + bias_data[2:4] + bias_data[0:2]
    bias_int = int(bias_reversed, 16)
    return bias_int

class TimezoneConversionException(Exception):
    """Exception in Registry Parser"""
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

