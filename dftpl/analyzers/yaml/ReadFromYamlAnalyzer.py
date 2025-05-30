__author__ = ['Java Kanaya Prada']

from typing import List 
from dftpl.analyzers.yaml.KeyProcessor import KeyProcessor
from dftpl.events.BaseEvent import BaseEvent
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.rules.Rule import KeyDefinition, ReasoningDefinition, Rule
from datetime import datetime


def Run(low_level_timeline: LowLevelTimeline, rule: Rule, start_id: int=0, end_id=None) -> HighLevelTimeline:
    """Runs the Google Search analyser"""
    if end_id is None:
        end_id = len(low_level_timeline.events)
    
    return CreateHighTimeline(low_level_timeline, rule, start_id, end_id)

def CreateHighTimeline(low_level_timeline: LowLevelTimeline, rule: Rule, start_id: int=0, end_id: int=None) -> HighLevelTimeline:

    # Find matching events
    matching_events = low_level_timeline.find_matching_events_in_id_range_with_rule(start_id, end_id, rule)
    
    # Create a high level timeline to store the results
    high_level_timeline = HighLevelTimeline()
    # Extract details from matching events
    for low_level_event in matching_events:
        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = low_level_event.id
        high_event.evidence_source = low_level_event.evidence
        high_event.category = rule.category
        high_event.plugin = low_level_event.plugin
        high_event.files = low_level_event.path
        
        # Set timestamps
        high_event.add_time(low_level_event.date_time_min)
        if hasattr(low_level_event, "date_time_iso"):
            high_event.date_time_iso = datetime.fromisoformat(
                low_level_event.date_time_min
            )

        if (rule.is_sigma_rule): 
            high_event.description = rule.description
        else:
            high_event.type = rule.high_level_event.type
            # Process each key definition
            process_keys(high_event, low_level_event, rule.high_level_event.keys)

            # Set description after key definition
            high_event.description = format_description(
                    rule.high_level_event.description, high_event
                )
                        
            # Create and set trigger
            if rule.reasoning:
                trigger = create_trigger(rule.reasoning, low_level_event)
                high_event.trigger = trigger
        

        # Get supporting events
        if hasattr(low_level_event, "id"):
            supporting_events = low_level_timeline.get_supporting_events(
                low_level_event.id
            )
            high_event.supporting = supporting_events

        # Add to timeline
        high_level_timeline.add_event(high_event)
                

    return high_level_timeline

def process_keys(
    high_event: HighLevelEvent,
    low_level_event: LowLevelEvent,
    key_definitions: List[KeyDefinition],
) -> None:
    """Process key definitions and set values in high-level event"""
    key_processor = KeyProcessor()

    for key_def in key_definitions:
        try:
            # Process the key using our new processor
            value = key_processor.process_key(
                key_def,
                low_level_event,
            )

            # Set the key
            if value is not None:
                high_event.set_keys(key_def.name, value)

        except Exception as e:
            print(f"Error processing key {key_def.name}: {str(e)}")
            high_event.set_keys(key_def.name, None)

def create_trigger(reasoning: "ReasoningDefinition", low_level_event: LowLevelEvent) -> ReasoningArtefact:
    """Create a reasoning artifact from the rule's reasoning definition"""
    trigger = ReasoningArtefact()
    trigger.id = low_level_event.id
    trigger.description = format_description(
        reasoning.description, low_level_event
    )
    trigger.test_event = {
        "type": low_level_event.type,
        "evidence": low_level_event.evidence,
    }
    return trigger

def format_description(description_template: str, event: BaseEvent) -> str:
    """Format the description template with event data"""
    try:
        # First try to format using any available keys in the low level event
        return description_template.format(**event.to_dict())
    except:  # noqa: E722
        # If that fails, return the template as is
        return description_template
