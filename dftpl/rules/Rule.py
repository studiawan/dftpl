from dataclasses import dataclass, field
from datetime import datetime, date
from typing import List, Dict, Any, Optional, Union
from enum import Enum

class RuleStatus(Enum):
    """Valid status values for rules"""
    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"
    
class RuleLevel(Enum):
    """Valid level values for rules"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    

@dataclass
class DetectionDefinition:
    """Represents the detection configuration in a rule"""

    keywords: Union[List[str], Dict[str, List[str]]]
    condition: str = "keywords"
    modifiers: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionDefinition":
        if not isinstance(data, dict):
            raise ValueError("Detection definition must be a dictionary")

        keywords_data = data.get("keywords", [])
        condition = data.get("condition", "keywords")
        modifiers = []

        if isinstance(keywords_data, dict):
            modifier_key = next(iter(keywords_data))
            if modifier_key.startswith("|"):
                modifiers = [m for m in modifier_key.split("|") if m]
                keywords_data = keywords_data[modifier_key]

        return cls(
            keywords=keywords_data,
            condition=condition,
            modifiers=modifiers,
        )
        
    def validate(self) -> List[str]:
        """Validate the detection configuration"""
        errors = []

        # Validate keywords
        if not self.keywords:
            errors.append("At least one keyword is required")

        # Validate modifiers
        valid_modifiers = {'all', 're'}
        for modifier in self.modifiers:
            if modifier not in valid_modifiers:
                errors.append(f"Invalid modifier: {modifier}")

        return errors


@dataclass
class KeyDefinition:
    """Defines a key in the high-level event configuration"""
    name: str
    source: str  # Name of the utility function to call

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyDefinition":
        return cls(
            name=data.get("name", ""),
            source=data.get("source", "")
        )


@dataclass
class HighLevelEventDefinition:
    """Defines the structure of a high-level event in the rule"""

    type: str
    description: str
    keys: List[KeyDefinition]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HighLevelEventDefinition":
        return cls(
            type=data.get("type", ""),
            description=data.get("description", ""),
            keys=[KeyDefinition.from_dict(k) for k in data.get("keys", [])],
        )


@dataclass
class ReasoningDefinition:
    """Defines the reasoning section in the rule"""
    description: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReasoningDefinition":
        return cls(
            description=data.get("description", ""), 
        )


@dataclass
class Rule:
    """Represents a detection rule with all its components"""

    title: str
    id: str
    description: str
    category: str
    detection: DetectionDefinition
    high_level_event: Optional[HighLevelEventDefinition] = None
    reasoning: Optional[ReasoningDefinition] = None
    status: RuleStatus = field(default=RuleStatus.EXPERIMENTAL)
    level: RuleLevel = field(default=RuleLevel.INFORMATIONAL)
    author: Optional[str] = None
    date: Optional[datetime] = None
    modified: Optional[datetime] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    is_sigma_rule: bool = field(default=False)

    @classmethod
    def from_yaml(cls, yaml_data: Dict) -> "Rule":
        # Parse dates if they exist
        date_obj = None
        if "date" in yaml_data:
            if isinstance(yaml_data["date"], (datetime, date)):
                # Already a datetime object
                date_obj = yaml_data["date"]
            else:
                # Try to parse from string
                try:
                    date_obj = datetime.strptime(yaml_data["date"], "%Y/%m/%d")
                except ValueError:
                    try:
                        date_obj = datetime.strptime(yaml_data["date"], "%Y-%m-%d")
                    except ValueError:
                        pass

        # Similar modification for 'modified' field
        modified_obj = None
        if "modified" in yaml_data:
            if isinstance(yaml_data["modified"], (datetime, date)):
                # Already a datetime object
                modified_obj = yaml_data["modified"]
            else:
                # Try to parse from string
                try:
                    modified_obj = datetime.strptime(yaml_data["modified"], "%Y/%m/%d")
                except ValueError:
                    try:
                        modified_obj = datetime.strptime(yaml_data["modified"], "%Y-%m-%d")
                    except ValueError:
                        pass
                        

        # Parse detection configuration
        detection_data = yaml_data.get("detection", {})
        detection = DetectionDefinition.from_dict(detection_data)

        # Determine if this is a Sigma rule or a custom event reconstruction rule
        is_sigma_rule = "high_level_event" not in yaml_data
        
        # Parse high level event definition if available
        high_level_event = None
        if "high_level_event" in yaml_data:
            high_level_event_data = yaml_data.get("high_level_event", {})
            high_level_event = HighLevelEventDefinition.from_dict(high_level_event_data)

        # Parse reasoning if it exists
        reasoning = None
        if "reasoning" in yaml_data:
            reasoning_data = yaml_data.get("reasoning")
            reasoning = ReasoningDefinition.from_dict(reasoning_data) if reasoning_data else None

        # Create the rule
        rule = cls(
            title=yaml_data.get("title", ""),
            id=yaml_data.get("id", ""),
            description=yaml_data.get("description", ""),
            category=yaml_data.get("category", "Unknown"),
            detection=detection,
            high_level_event=high_level_event,
            reasoning=reasoning,
            status=yaml_data.get("status", "experimental"),
            level=yaml_data.get("level"),
            author=yaml_data.get("author"),
            date=date_obj,
            modified=modified_obj,
            references=yaml_data.get("references", []),
            tags=yaml_data.get("tags", []),
            is_sigma_rule=is_sigma_rule
        )
        
        return rule

    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary"""
        detection_dict = {
            "keywords": self.detection.keywords,
            "condition": self.detection.condition
        }
        
        # Add modifiers if present
        if self.detection.modifiers:
            modifier_key = '|' + '|'.join(self.detection.modifiers)
            detection_dict = {
                "keywords": {
                    modifier_key: self.detection.keywords
                },
                "condition": self.detection.condition
            }
        
        result = {
            "title": self.title,
            "id": self.id,
            "description": self.description,
            "category": self.category,
            "status": self.status,
            "author": self.author,
            "date": self.date.strftime("%Y/%m/%d") if self.date else None,
            "modified": self.modified.strftime("%Y/%m/%d") if self.modified else None,
            "references": self.references,
            "tags": self.tags,
            "detection": detection_dict,
        }
        
        # Add high_level_event if available
        if self.high_level_event:
            result["high_level_event"] = {
                "type": self.high_level_event.type,
                "description": self.high_level_event.description,
                "keys": [
                    {
                        "name": k.name,
                        "source": k.source
                    }
                    for k in self.high_level_event.keys
                ],
            }
            
        # Add reasoning if available
        if self.reasoning:
            result["reasoning"] = {
                "description": self.reasoning.description,
                "found_in": self.reasoning.found_in,
            }
            
        return result