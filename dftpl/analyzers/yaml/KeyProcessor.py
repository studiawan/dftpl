from typing import Any, Dict, List
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.rules.Rule import KeyDefinition, KeySourceType
from dftpl.utils.web import Utils


class KeyProcessor:
    """Handles processing of different key types"""

    def __init__(self):
        self.utils = Utils()

    def process_key(
        self,
        key_def: KeyDefinition,
        low_level_event: "LowLevelEvent",
        existing_keys: Dict[str, Any] = None,
    ) -> Any:
        """Process a key based on its source type"""
        try:
            if key_def.source_type == KeySourceType.UTILS:
                return self._process_utils_key(key_def, low_level_event)
            elif key_def.source_type == KeySourceType.ATTRIBUTE:
                return self._process_attribute_key(key_def, low_level_event)
            else:
                raise ValueError(f"Unknown source type: {key_def.source_type}")
        except Exception as e:
            print(f"Error processing key {key_def.name}: {str(e)}")
            return None

    def _process_utils_key(
        self, key_def: KeyDefinition, low_level_event: "LowLevelEvent"
    ) -> Any:
        """Process utility function based keys"""
        if not hasattr(self.utils, key_def.source_name):
            raise ValueError(f"Utility method {key_def.source_name} not found")

        util_method = getattr(self.utils, key_def.source_name)
        args = self._resolve_arguments(key_def.source_args, low_level_event)
        return util_method(*args)

    def _process_attribute_key(
        self, key_def: KeyDefinition, low_level_event: "LowLevelEvent"
    ) -> Any:
        """Process direct attribute access"""
        # Handle nested attributes (e.g., "each_low_event.path")
        obj = low_level_event
        attrs = key_def.source_name.split(".")

        # Skip the "each_low_event" prefix if present
        if attrs[0] == "each_low_event":
            attrs = attrs[1:]

        for attr in attrs:
            if not hasattr(obj, attr):
                raise AttributeError(f"Attribute {attr} not found")
            obj = getattr(obj, attr)
        return obj

    def _resolve_arguments(
        self, args: List[str], low_level_event: "LowLevelEvent"
    ) -> List[Any]:
        """Resolve arguments, handling both direct values and object attributes"""
        resolved_args = []
        for arg in args:
            if arg.startswith("each_low_event."):
                _, attr = arg.split(".")
                if not hasattr(low_level_event, attr):
                    raise AttributeError(
                        f"Attribute {attr} not found in low level event"
                    )
                resolved_args.append(getattr(low_level_event, attr))
            else:
                # Handle literal values (strip quotes if present)
                resolved_args.append(arg.strip("\"'"))
        return resolved_args
