__author__ = ['Java Kanaya Prada']

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline

from dftpl.utils import *

def Run(low_timeline: LowLevelTimeline, yaml_rule, start_id: int=0, end_id=None) -> HighLevelTimeline:
    """Runs the Google Search analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return CreateHighTimeline(low_timeline, yaml_rule, start_id, end_id)

def CreateHighTimeline(low_timeline: LowLevelTimeline, yaml_rule, start_id: int=0, end_id: int=None) -> HighLevelTimeline:
    """Finds Google searches based on URL structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = yaml_rule['test_event'][0]['type']
    test_event.evidence = yaml_rule['test_event'][1]['evidence']
    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)
    
    # Extract details from matching events
    for each_low_event in trigger_matches:
        if re.search(yaml_rule['high_level_event'][0]['pattern'], eval(yaml_rule['high_level_event'][0]['match_with'])):
            # print("here")
            # Create a high level event
            high_event = HighLevelEvent()
            high_event.id = each_low_event.id
            high_event.add_time(each_low_event.date_time_min)
            high_event.evidence_source = each_low_event.evidence
            high_event.type = yaml_rule['high_level_event'][1]['type']
            high_event.category = yaml_rule['category']
            high_event.device = each_low_event.plugin
            high_event.files = each_low_event.path

            # Iterate through each key
            for key in yaml_rule['high_level_event'][3]['keys']:  
                name = key['name']
                source_type = key['source_type']
                source_name = key['source_name']
                print(source_name)
                if source_type == "utils":
                    source_args = key['source_args']
                    print(source_args)
                    print("here")
                    args = []
                    for arg in source_args:
                        # Check if the argument is a string or a character in single or double quotes
                        if isinstance(arg, str) and (
                            (arg.startswith('"') and arg.endswith('"')) or 
                            (arg.startswith("'") and arg.endswith("'"))
                        ):
                            # Remove the surrounding quotes and append to args
                            args.append(arg[1:-1])
                        else:
                            # Evaluate if it's a variable
                            args.append(eval(arg))
                    high_event.set_keys(name, eval(source_name)(*args))  
                elif source_type == "attribute":
                    high_event.set_keys(name, eval(source_name))
                    
                
            
            high_event.description = yaml_rule['high_level_event'][2]['description']
            
            high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

            # Create a reasoning artefact
            reasoning = ReasoningArtefact()
            reasoning.id = each_low_event.id
            reasoning.description = yaml_rule['reasoning'][0]['description'] + eval(yaml_rule['reasoning'][0]['found_in'])
            reasoning.test_event = test_event
            reasoning.provenance = each_low_event.provenance

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning.to_dict()

            # Add the high level event to the high level timeline
            high_timeline.add_event(high_event)

    return high_timeline

