"""
Implementation of parser that would convert the json incident to string representation  and
json intrusion sets to IntrusionSet object.
"""

import json
import typing
from dataclasses import asdict, dataclass, field
from typing import List, Mapping, Union


@dataclass
class Entity:
    """The abstract class that would be further used for inheritance."""

    identifier: str
    entity_type: str = ""
    semantic_id: str = ""
    is_subject: bool = False
    relation: str = ""

    def __hash__(self):
        return hash(self.entity_type + self.identifier)


@dataclass(eq=False)
class AttackPattern(Entity):
    """The Attack Pattern class"""

    entity_type: str = "attack-pattern"


@dataclass(eq=False)
class Malware(Entity):
    """The Malware class"""

    entity_type: str = "malware"


@dataclass(eq=False)
class Tool(Entity):
    """The Tool class"""

    entity_type: str = "tool"


@dataclass(eq=False)
class Identity(Entity):
    """The Identity class"""

    entity_type: str = "identity"


@dataclass(eq=False)
class Location(Entity):
    """The Location class"""

    entity_type: str = "location"


@dataclass(eq=False)
class Vulnerability(Entity):
    """The Vulnerability class"""

    entity_type: str = "vulnerability"


@dataclass(eq=False)
class Indicator(Entity):
    """The Indicator class"""

    entity_type: str = "indicator"


@dataclass
class IntrusionSet:
    """The Intrusion Set class"""

    identifier: str
    entity_type: str = "intrusion-set"
    empty: bool = True

    attack_patterns: List[AttackPattern] = field(default_factory=list)
    malwares: List[Malware] = field(default_factory=list)
    tools: List[Tool] = field(default_factory=list)
    identities: List[Identity] = field(default_factory=list)
    locations: List[Location] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    indicators: List[Indicator] = field(default_factory=list)

    @typing.no_type_check
    def add_related_entity(self, entity: Entity) -> None:
        """Add entity for intrusion set"""
        instance_map = {
            AttackPattern: self.attack_patterns,
            Malware: self.malwares,
            Tool: self.tools,
            Identity: self.identities,
            Location: self.locations,
            Vulnerability: self.vulnerabilities,
            Indicator: self.indicators,
        }
        destination = instance_map[type(entity)]
        if entity in destination:
            return
        destination.append(entity)
        self.empty = False

    @property
    def __dict__(self):
        return asdict(self)

    @property
    def json(self):
        """Return json dumps."""
        return json.dumps(self.__dict__)


def get_semantic_id_from_attack_pattern(attack_pattern: dict) -> str:
    """Get the name for the attack pattern

    :return: the string with the name

    >>> data = {"x_mitre_id": "T1003.001"}
    >>> get_semantic_id_from_attack_pattern(data)
    'attack-pattern-T1003'
    >>> data = {"x_mitre_id": "T1100"}
    >>> get_semantic_id_from_attack_pattern(data)
    'attack-pattern-T1100'
    """
    x_mitre_id = attack_pattern.get("x_mitre_id", "")
    return "attack-pattern-" + x_mitre_id.split(".")[0].replace(" ", "")


def get_semantic_id_from_malware(malware: dict) -> str:
    """Get the name for the malware

    :return: the string with the name

    >>> data = {"name": "Malware Name"}
    >>> get_semantic_id_from_malware(data)
    'malware-MalwareName'
    """
    name = malware.get("name", "").replace(" ", "")
    return "malware-" + name


def get_semantic_id_from_tool(tool: dict) -> str:
    """Get the name for the tools

    :return: the string with the name

    >>> data = {"name": "Tool Name"}
    >>> get_semantic_id_from_tool(data)
    'tool-ToolName'
    """
    name = tool.get("name", "").replace(" ", "")
    return "tool-" + name


def get_semantic_id_from_identity(identity: dict) -> str:
    """Get the name for the tools

    :return: the string with the name

    >>> data = {"id": "identity--f11b0831-e7e6-5214-9431-ccf054e53e94"}
    >>> get_semantic_id_from_identity(data)
    'identity--f11b0831-e7e6-5214-9431-ccf054e53e94'
    """
    return identity.get("id", "")


def get_semantic_id_from_location(location: dict) -> str:
    """Get the name for the tools

    :return: the string with the name

    >>> data = {"id": "location--f11b0831-e7e6-5214-9431-ccf054e53e94"}
    >>> get_semantic_id_from_location(data)
    'location--f11b0831-e7e6-5214-9431-ccf054e53e94'
    """
    return location.get("id", "")


def get_semantic_id_from_vulnerability(vulnerability: dict) -> str:
    """Get the name for the tools

    :return: the string with the name

    >>> data = {"id": "vulnerability--f11b0831-e7e6-5214-9431-ccf054e53e94"}
    >>> get_semantic_id_from_vulnerability(data)
    'vulnerability--f11b0831-e7e6-5214-9431-ccf054e53e94'
    """
    return vulnerability.get("id", "")


def get_semantic_id_from_indicator(indicator: dict) -> str:
    """Get the name for the tools

    :return: the string with the name

    >>> data = {"id": "indicator--f11b0831-e7e6-5214-9431-ccf054e53e94"}
    >>> get_semantic_id_from_indicator(data)
    'indicator--f11b0831-e7e6-5214-9431-ccf054e53e94'
    """
    return indicator.get("id", "")


def incident_json_to_str(incident_json: dict) -> str:
    """Convert json to string representation."""
    incident_list = []
    value_functions = {
        "attack-pattern": get_semantic_id_from_attack_pattern,
        "malware": get_semantic_id_from_malware,
        "tool": get_semantic_id_from_tool,
        "identity": get_semantic_id_from_identity,
        "location": get_semantic_id_from_location,
        "vulnerability": get_semantic_id_from_vulnerability,
        "indicator": get_semantic_id_from_indicator,
    }
    for incident_val in incident_json.get("objects", []):
        incident_val_id = incident_val["id"]
        for keyword, getter_func in value_functions.items():
            if incident_val_id.startswith(keyword):
                incident_list.append(getter_func(incident_val))
                break
    return " ".join(incident_list)


def build_intrusion_set_repr_json(bundle_objects: list) -> Union[IntrusionSet, None]:
    """Build IS representation via JSON parsing.
    Assumptions made:
      * A file (i.e. JSON-ized STIX bundle) represents single Intrusion Set;
      * The file incorporates only entities connected with the Intrusion Set;
      * The file incorporates only relations of the entities with the Intrusion Set.
    """

    instance_map = {
        # STIX_TYPE: (Parser-specific class type, Type-specific handler)
        "attack-pattern": (AttackPattern, get_semantic_id_from_attack_pattern),
        "malware": (Malware, get_semantic_id_from_malware),
        "tool": (Tool, get_semantic_id_from_tool),
        "identity": (Identity, get_semantic_id_from_identity),
        "location": (Location, get_semantic_id_from_location),
        "vulnerability": (Vulnerability, get_semantic_id_from_vulnerability),
        "indicator": (Indicator, get_semantic_id_from_indicator),
    }

    intrusion_sets = list(filter(lambda item: item["type"] == "intrusion-set", bundle_objects))
    if not intrusion_sets:
        return None

    intrusion_set = intrusion_sets[0]
    intrusion_set_shadow = IntrusionSet(identifier=intrusion_set["id"])
    related_objects = {}

    for stix_type, stix_value in instance_map.items():
        semantic_handler = stix_value[1]
        selection = list(filter(lambda item: item["type"] == stix_type, bundle_objects))
        related_objects.update({item["id"]: (stix_type, semantic_handler(item)) for item in selection})

    selection = list(
        filter(
            lambda item: (item["type"] == "relationship") & (item.get("source_ref", None) == intrusion_set["id"]),
            bundle_objects,
        )
    )
    for relationship in selection:
        target_ref = relationship.get("target_ref", None)
        related_object = related_objects.get(target_ref, None)
        if related_object:
            class_type = instance_map[related_objects[relationship["target_ref"]][0]][0]
            item_shadow = class_type(identifier=relationship["target_ref"])
            item_shadow.is_subject = False
            item_shadow.relation = relationship["relationship_type"]
            item_shadow.semantic_id = related_object[1]
            intrusion_set_shadow.add_related_entity(item_shadow)

    selection = list(
        filter(
            lambda item: (item["type"] == "relationship") & (item.get("target_ref", None) == intrusion_set["id"]),
            bundle_objects,
        )
    )
    for relationship in selection:
        source_ref = relationship.get("source_ref", None)
        related_object = related_objects.get(source_ref, None)
        if related_object:
            class_type = instance_map[related_objects[relationship["source_ref"]][0]][0]
            item_shadow = class_type(identifier=relationship["source_ref"])
            item_shadow.is_subject = True
            item_shadow.relation = relationship["relationship_type"]
            item_shadow.semantic_id = related_object[1]
            intrusion_set_shadow.add_related_entity(item_shadow)

    return intrusion_set_shadow


def get_intrusion_set_name(objects):
    """Return intrusion set name."""
    for object_val in objects:
        if object_val["id"].startswith("intrusion-set"):
            return str(object_val["name"] + "_" + object_val["id"])
    return " "


def get_instrusion_sets_stats(intrusion_sets_data: list) -> Mapping[str, IntrusionSet]:
    """Get intrusion sets stats."""
    intrusion_sets = {}

    for intrusion_set in intrusion_sets_data:
        objects = intrusion_set["objects"]
        representation = build_intrusion_set_repr_json(objects)
        if representation:
            id_str = get_intrusion_set_name(objects)
            intrusion_sets[id_str] = representation

    return intrusion_sets
