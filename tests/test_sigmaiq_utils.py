import pytest
from sigmaiq.utils.sigmaiq.sigmaiq_utils import create_sigma_rule_obj

# Fixtures
from tests.test_backend_factory import sigma_rule, sigma_rule_yaml_str, sigma_rule_dict, sigma_collection
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection


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
