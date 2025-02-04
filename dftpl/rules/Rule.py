from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum


class KeySourceType(Enum):
    UTILS = "utils"  # Function-based processing
    ATTRIBUTE = "attribute"  # Direct attribute access

@dataclass
class KeyDefinition:
    """Defines a key in the high-level event configuration"""

    name: str
    source_type: KeySourceType
    source_name: str
    source_args: Optional[List[str]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyDefinition":
        return cls(
            name=data.get("name", ""),
            source_type=KeySourceType(data.get("source_type", "").lower()),
            source_name=data.get("source_name", ""),
            source_args=data.get("source_args", []),
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
    found_in: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReasoningDefinition":
        return cls(
            description=data.get("description", ""), found_in=data.get("found_in", "")
        )


@dataclass
class Rule:
    """Represents a detection rule with all its components"""

    title: str
    id: str
    description: str
    category: str
    keywords: List[str]
    high_level_event: HighLevelEventDefinition
    reasoning: Optional[ReasoningDefinition] = None
    status: str = field(default="experimental")
    author: Optional[str] = None
    date: Optional[datetime] = None
    modified: Optional[datetime] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, yaml_data: Dict) -> "Rule":
        # Parse dates if they exist
        date = None
        if "date" in yaml_data:
            try:
                date = datetime.strptime(yaml_data["date"], "%Y/%m/%d")
            except ValueError:
                try:
                    date = datetime.strptime(yaml_data["date"], "%Y-%m-%d")
                except ValueError:
                    pass

        modified = None
        if "modified" in yaml_data:
            try:
                modified = datetime.strptime(yaml_data["modified"], "%Y/%m/%d")
            except ValueError:
                try:
                    modified = datetime.strptime(yaml_data["modified"], "%Y-%m-%d")
                except ValueError:
                    pass

        # Parse high level event definition
        high_level_event_data = yaml_data.get("high_level_event", {})
        high_level_event = HighLevelEventDefinition.from_dict(high_level_event_data)

        # Parse reasoning if it exists
        reasoning_data = yaml_data.get("reasoning")
        reasoning = (
            ReasoningDefinition.from_dict(reasoning_data) if reasoning_data else None
        )

        return cls(
            title=yaml_data.get("title", ""),
            id=yaml_data.get("id", ""),
            description=yaml_data.get("description", ""),
            category=yaml_data.get("category", "Unknown"),
            keywords=yaml_data.get("detection", {}).get("keywords", []),
            high_level_event=high_level_event,
            reasoning=reasoning,
            status=yaml_data.get("status", "experimental"),
            author=yaml_data.get("author"),
            date=date,
            modified=modified,
            references=yaml_data.get("references", []),
            tags=yaml_data.get("tags", []),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary"""
        return {
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
            "detection": {"keywords": self.keywords},
            "high_level_event": {
                "type": self.high_level_event.type,
                "description": self.high_level_event.description,
                "keys": [
                    {
                        "name": k.name,
                        "source_type": k.source_type,
                        "source_name": k.source_name,
                        "source_args": k.source_args,
                    }
                    for k in self.high_level_event.keys
                ],
            },
            "reasoning": {
                "description": self.reasoning.description,
                "found_in": self.reasoning.found_in,
            }
            if self.reasoning
            else None,
        }
