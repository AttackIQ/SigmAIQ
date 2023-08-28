from typing import Union
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection


def create_sigma_rule_obj(sigma_rule: Union[SigmaRule, SigmaCollection, dict, str, list]):
    """Checks sigma_rule to ensure it's a SigmaRule or SigmaCollection object. It can also be a valid Sigma rule
    representation in a dict or yaml str (or list of valid dicts/yaml strs) that can be used with SigmaRule class methods to
    create a valid SigmaRule object. The following checks are performed:
        - If the object is a SigmaRule or SigmaCollection object, return the object.
        - If the object is a list, we will recursively check each element in the list and return a SigmaCollection
        of the returned objects
        - If the object is a dict, use SigmaRule.from_dict(sigma_rule) to create a new SigmaRule object.
        - If the object is a str, use SigmaRule.from_yaml(sigma_rule) to create a new SigmaRule object.

    :param sigma_rule: A list of, or single SigmaRule, SigmaCollection, or valid dict/yaml str that will be
    returned as a SigmaRule or SigmaCollection object.
    :return: SigmaRule or SigmaCollection object as-is or created using SigmaRule classmethods.
    """

    if isinstance(sigma_rule, SigmaRule) or isinstance(sigma_rule, SigmaCollection):  # We're good
        return sigma_rule
    if isinstance(sigma_rule, list):  # Try to make collection from list of objects, recursively
        return SigmaCollection([create_sigma_rule_obj(s) for s in sigma_rule])
    if isinstance(sigma_rule, dict):  # Create one from dict
        return SigmaRule.from_dict(sigma_rule)
    if isinstance(sigma_rule, str):  # from YAML str
        return SigmaRule.from_yaml(sigma_rule)
    raise TypeError(
        f"Invalid type '{type(sigma_rule)}' for `sigma_rule`. "
        f"Use a SigmaRule, SigmaCollection, dict, str, or list of these types instead."
    )
