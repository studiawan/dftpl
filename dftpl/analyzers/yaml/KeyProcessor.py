# analyzers/yaml/KeyProcessor.py

from typing import Any
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.rules.Rule import KeyDefinition
from dftpl.utils.util import Utils


class KeyProcessor:
    """Handles processing of different key types - simplified version"""

    def __init__(self):
        self.utils = Utils()

    def process_key(
        self,
        key_def: KeyDefinition,
        low_level_event: LowLevelEvent,
    ) -> Any:
        """Process a key by calling the specified utility function"""
        try:
            # Check if the utility function exists
            if not hasattr(self.utils, key_def.source):
                raise ValueError(f"Utility method {key_def.source} not found")

            # Get the utility function
            util_method = getattr(self.utils, key_def.source)
            
            # Call the function with the low-level event
            return util_method(low_level_event)
            
        except Exception as e:
            print(f"Error processing key {key_def.name} with source {key_def.source}: {str(e)}")
            return None