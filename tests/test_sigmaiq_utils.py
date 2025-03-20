import datetime
import pytest
import yaml
from sigmaiq.utils.sigmaiq.sigmaiq_utils import create_sigma_rule_obj, _is_v1_schema, _convert_to_v2_schema

# Existing fixtures
from tests.test_backend_factory import sigma_rule, sigma_rule_yaml_str, sigma_rule_dict, sigma_collection
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection


# New fixtures for schema conversion tests
@pytest.fixture
def v1_rule_data():
    return {
        "id": "12345678-abcd-abcd-1234-1234567890ab",
        "title": "Test Rule",
        "date": "2023/04/15",
        "tags": ["attack.execution", "attack_persistence", "cve.2023.1234", "detection.threat_hunting"],
        "related": [{"type": "obsoletes", "id": "12345678-abcd-abcd-1234-1234567890ab"}],
        "modified": "2023/04/15",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_img": {"Image|endswith": "\\regedit.exe", "OriginalFileName": "REGEDIT.EXE"},
            "condition": "all of selection_* and not all of filter_*",
        },
    }


@pytest.fixture
def v2_rule_data():
    return {
        "id": "12345678-abcd-abcd-1234-1234567890ab",
        "title": "Test Rule",
        "date": "2023-04-15",
        "tags": ["attack.execution", "attack.persistence", "cve.2023.1234", "detection.threat_hunting"],
        "related": [{"type": "obsolete", "id": "12345678-abcd-abcd-1234-1234567890ab"}],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_img": {"Image|endswith": "\\regedit.exe", "OriginalFileName": "REGEDIT.EXE"},
            "condition": "all of selection_* and not all of filter_*",
        },
    }


# Existing tests
def test_create_sigma_rule_obj_sigma_rule(sigma_rule):
    """Tests creating a SigmaRule object from a SigmaRule, aka just return the rule"""
    sigma_rule = sigma_rule
    print(type(sigma_rule))
    assert isinstance(create_sigma_rule_obj(sigma_rule), SigmaRule)


def test_create_sigma_rule_obj_sigma_collection(sigma_collection):
    """Tests creating a SigmaRule object from a SigmaCollection, aka just return the collection"""
    assert isinstance(create_sigma_rule_obj(sigma_collection), SigmaCollection)


def test_create_sigma_rule_obj_sigma_rule_yaml_str(sigma_rule_yaml_str):
    """Tests creating a SigmaRule object from a valid SigmaRule YAML str"""
    assert isinstance(create_sigma_rule_obj(sigma_rule_yaml_str), SigmaRule)


def test_create_sigma_rule_obj_sigma_rule_dict(sigma_rule_dict):
    """Tests creating a SigmaRule object from a valid SigmaRule dict"""
    assert isinstance(create_sigma_rule_obj(sigma_rule_dict), SigmaRule)


def test_create_sigma_rule_obj_invalid_type():
    """Tests creating a SigmaRule object from an invalid type"""
    with pytest.raises(TypeError):
        create_sigma_rule_obj(1)  # Invalid type


def test_create_sigma_rule_obj_invalid_type_list():
    """Tests creating a SigmaRule object from an invalid type list"""
    with pytest.raises(TypeError):
        create_sigma_rule_obj([1])  # Invalid type list


def test_create_sigma_rule_objsigma_rule_list(sigma_rule, sigma_rule_yaml_str):
    """Tests creating a SigmaRule objects from a list"""
    assert isinstance(create_sigma_rule_obj([sigma_rule, sigma_rule_yaml_str]), SigmaCollection)


# New schema conversion tests
class TestSchemaDetection:
    """Tests for v1 schema detection"""

    def test_v1_date_detection(self):
        assert _is_v1_schema({"date": "2023/04/15"})
        assert not _is_v1_schema({"date": "2023-04-15"})

    def test_v1_tags_detection(self):
        assert _is_v1_schema({"tags": ["attack-execution"]})
        assert _is_v1_schema({"tags": ["attack-persistence"]})
        assert not _is_v1_schema({"tags": ["attack.execution"]})

    def test_v1_related_detection(self):
        assert _is_v1_schema({"related": [{"type": "obsoletes"}]})
        assert not _is_v1_schema({"related": [{"type": "obsolete"}]})

    def test_non_dict_input(self):
        assert not _is_v1_schema(None)
        assert not _is_v1_schema([])
        assert not _is_v1_schema("string")


class TestSchemaConversion:
    """Tests for v1 to v2 schema conversion"""

    def test_date_conversion(self, v1_rule_data, v2_rule_data):
        converted = _convert_to_v2_schema(v1_rule_data)
        assert converted["date"] == v2_rule_data["date"]

    def test_tags_conversion(self, v1_rule_data, v2_rule_data):
        converted = _convert_to_v2_schema(v1_rule_data)
        assert converted["tags"] == v2_rule_data["tags"]

    def test_related_conversion(self, v1_rule_data, v2_rule_data):
        converted = _convert_to_v2_schema(v1_rule_data)
        assert converted["related"] == v2_rule_data["related"]

    def test_invalid_date_handling(self):
        rule_data = {"date": "invalid/date/format"}
        converted = _convert_to_v2_schema(rule_data)
        assert converted["date"] == "invalid/date/format"  # Should preserve invalid date

    def test_missing_fields_handling(self):
        rule_data = {"title": "Test Rule"}  # No convertible fields
        converted = _convert_to_v2_schema(rule_data)
        assert converted == rule_data  # Should return unchanged


class TestSchemaConversionIntegration:
    """Integration tests for schema conversion with create_sigma_rule_obj"""

    def test_dict_conversion(self, v1_rule_data):
        rule = create_sigma_rule_obj(v1_rule_data)
        assert isinstance(rule, SigmaRule)
        assert rule.date and isinstance(rule.date, datetime.date)
        assert rule.tags and all("." in str(tag) for tag in rule.tags if "attack" in str(tag))

    def test_yaml_string_conversion(self, v1_rule_data):
        yaml_str = yaml.dump(v1_rule_data)
        rule = create_sigma_rule_obj(yaml_str)
        assert isinstance(rule, SigmaRule)
        assert rule.date and isinstance(rule.date, datetime.date)
        assert rule.tags and all("." in str(tag) for tag in rule.tags if "attack" in str(tag))

    def test_list_conversion(self, v1_rule_data):
        rules = create_sigma_rule_obj([v1_rule_data, v1_rule_data])
        assert isinstance(rules, SigmaCollection)
        assert len(rules.rules) == 2
        for rule in rules.rules:
            assert rule.date and isinstance(rule.date, datetime.date)
            assert rule.tags and all("." in str(tag) for tag in rule.tags if "attack" in str(tag))
