"""Unit tests for parser module"""
import json
from pathlib import Path, PurePath

from attribution_tools import parsers

DATA_LOCATION = "tests/data"
INCIDENT_JSON_FILE_NAME = "incident.json"
INCIDENT_TXT_FILE_NAME = "incident_str.txt"


def test_get_incident_json_to_str():
    """Check if json incident is correctly converted to string"""
    cwd = Path().absolute()

    incident_txt_location = PurePath(cwd, DATA_LOCATION, INCIDENT_TXT_FILE_NAME)
    with open(incident_txt_location) as filename:
        incident_str_expected = filename.read().replace("\n", "")

    incident_json_location = PurePath(cwd, DATA_LOCATION, INCIDENT_JSON_FILE_NAME)
    with open(incident_json_location, "rb") as filename:
        incident_json = json.load(filename)
    incident_str = parsers.incident_json_to_str(incident_json)
    assert incident_str_expected == incident_str, "The incident strings should match."
