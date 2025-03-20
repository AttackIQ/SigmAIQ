import pytest
import json

from sigmaiq.sigmaiq_backend_factory import SigmAIQBackend
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import SetStateTransformation
from sigmaiq.exceptions import InvalidSigmAIQBackend, InvalidOutputFormat


@pytest.fixture
def sigma_rule():
    """Fixture for a PySigma SigmaRule object"""
    return SigmaRule.from_yaml(
        """
            title: Test Rule
            id: 12345678-abcd-abcd-1234-1234567890ab
            status: test
            description: A Test Sigma Rule
            author: AttackIQ
            date: 2023-01-01
            modified: 2023-01-02
            tags:
                - attack.t1003
                - attack.t1003.001
                - attack.credential_access
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: valueA
                condition: sel
            falsepositives:
                - None
            level: high
        """
    )


@pytest.fixture
def sigma_rule_dict():
    """Fixture for a basic Sigma rule dict"""
    return {
        "title": "Test Rule",
        "id": "12345678-abcd-abcd-1234-1234567890ab",
        "status": "test",
        "description": "A Test Sigma Rule",
        "author": "AttackIQ",
        "date": "2023-01-01",
        "modified": "2023-01-02",
        "tags": ["attack.t1003", "attack.t1003.001", "attack.credential_access"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"sel": {"CommandLine": "valueA"}, "condition": "sel"},
        "falsepositives": ["None"],
        "level": "high",
    }


@pytest.fixture
def sigma_rule_yaml_str():
    """Fixture for a valid str YAML Sigma Rule"""
    return """
            title: Test Rule
            id: 12345678-abcd-abcd-1234-1234567890ab
            status: test
            description: A Test Sigma Rule
            author: AttackIQ
            date: 2023-01-01
            modified: 2023-01-02
            tags:
                - attack.t1003
                - attack.t1003.001
                - attack.credential_access
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: valueA
                condition: sel
            falsepositives:
                - None
            level: high
        """


@pytest.fixture
def sigma_rule_stix_shifter():
    """Special rule for testing the Stix backend with stix_shifter pipeline, as it has uncommon field mappings and
    errors when trying to convert common ones like CommandLine that are not included.
    """
    return SigmaRule.from_yaml(
        """
                title: Test Rule
                id: 12345678-abcd-abcd-1234-1234567890ab
                status: test
                description: A Test Sigma Rule
                author: AttackIQ
                date: 2023-01-01
                modified: 2023-01-02
                tags:
                    - attack.t1003
                    - attack.t1003.001
                    - attack.credential_access
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        severity: high
                    condition: sel
                falsepositives:
                    - None
                level: high
            """
    )


@pytest.fixture
def sigma_collection():
    """Fixture for a pySigma SigmaCollection object"""
    return SigmaCollection(
        [
            SigmaRule.from_yaml(
                """
            title: Test Rule 1
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: valueA
                condition: sel
        """
            ),
            SigmaRule.from_yaml(
                """
                title: Test Rule 2
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        CommandLine: valueB
                    condition: sel
            """
            ),
        ]
    )


@pytest.fixture
def processing_pipeline():
    """Fixture for a valid PySigma ProcessingPipeline object"""
    return ProcessingPipeline(
        name="Test Pipeline",
        priority=100,
        items=[
            ProcessingItem(
                identifier="Test ProcessingItem", transformation=SetStateTransformation(key="test_key", val="test_val")
            )
        ],
    )


@pytest.mark.parametrize("available_backend", list(SigmAIQBackend.display_available_backends().keys()))
def test_available_backends(available_backend):
    """Test if SigmAIQ backend objects can be instantiated by backend keyword"""
    assert SigmAIQBackend(backend=available_backend).create_backend()


@pytest.mark.parametrize("available_backend", list(SigmAIQBackend.display_available_backends().keys()))
def test_backend_conversion_rule(available_backend, sigma_rule):
    """Tests converting a basic SigmaRule object with a SigmAIQBackend object"""
    backend_obj = SigmAIQBackend(backend=available_backend).create_backend()
    output = backend_obj.translate(sigma_rule)
    assert isinstance(output, list)


@pytest.mark.parametrize("available_backend", list(SigmAIQBackend.display_available_backends().keys()))
def test_backend_conversion_collection(available_backend, sigma_collection):
    """Tests converting a basic SigmaCollection object with a SigmAIQBackend object"""
    backend_obj = SigmAIQBackend(backend=available_backend).create_backend()
    output = backend_obj.translate(sigma_collection)
    assert isinstance(output, list)


settings = []
backend_output_formats = SigmAIQBackend.display_backends_and_outputs()
for backend, data in backend_output_formats.items():
    output_formats = data.get("output_formats")
    for output_format in output_formats:
        settings.append((backend, output_format))


@pytest.mark.parametrize("backend_str, output_format_str", settings)
def test_backend_conversion_outputs(backend_str, output_format_str, sigma_rule):
    """Tests every inherited and custom output format defined in each backend when converting SigmaRules"""
    backend_obj = SigmAIQBackend(backend=backend_str, output_format=output_format_str).create_backend()
    output = backend_obj.translate(sigma_rule)
    assert isinstance(output, list)


@pytest.mark.parametrize("backend_str, output_format_str", settings)
def test_backend_conversion_outputs_sigma_collection(backend_str, output_format_str, sigma_collection):
    """Tests every inherited and custom output format defined in each backend when converting SigmaCollections"""
    backend_obj = SigmAIQBackend(backend=backend_str, output_format=output_format_str).create_backend()
    output = backend_obj.translate(sigma_collection)
    print(type(output))
    assert isinstance(output, list)


def test_invalid_backend():
    """Tests whether the correct exception is raised when an invalid backend is passed to factory"""
    with pytest.raises(InvalidSigmAIQBackend):
        SigmAIQBackend(backend="hunter2").create_backend()


@pytest.mark.parametrize("available_backend", list(SigmAIQBackend.display_available_backends().keys()))
def test_invalid_output_format(available_backend):
    """Tests whether the correct exception is raised when an invalid output format is passed to a factory for a
    specific backend"""
    with pytest.raises(InvalidOutputFormat):
        SigmAIQBackend(backend=available_backend, output_format="garbage").create_backend()


@pytest.mark.parametrize("available_backend", list(SigmAIQBackend.display_available_backends().keys()))
def test_basic_processing_pipeline_rule(available_backend, processing_pipeline, sigma_rule):
    """Tests whether the correct exception is raised when an invalid processing pipeline is passed to a backend"""
    backend_obj = SigmAIQBackend(backend=available_backend, processing_pipeline=processing_pipeline).create_backend()
    output = backend_obj.translate(sigma_rule)
    assert isinstance(output, list)


@pytest.mark.parametrize("available_backend", list(SigmAIQBackend.display_available_backends().keys()))
def test_basic_processing_pipeline_collection(available_backend, processing_pipeline, sigma_collection):
    """Tests whether the correct exception is raised when an invalid processing pipeline is passed to a backend"""
    backend_obj = SigmAIQBackend(backend=available_backend, processing_pipeline=processing_pipeline).create_backend()
    output = backend_obj.translate(sigma_collection)
    assert isinstance(output, list)


@pytest.mark.parametrize(
    "available_backend,associated_pipeline",
    [(k, vv) for k, v in SigmAIQBackend.display_all_associated_pipelines().items() for vv in v],
)
def test_associated_pipelines_rule(available_backend, associated_pipeline, sigma_rule, sigma_rule_stix_shifter):
    """Tests using backends with pipelines defined in their associated_pipelines attribute"""
    backend_obj = SigmAIQBackend(backend=available_backend, processing_pipeline=associated_pipeline).create_backend()

    output = (
        backend_obj.translate(sigma_rule)
        if associated_pipeline != "stix_shifter"
        else backend_obj.translate(sigma_rule_stix_shifter)
    )
    assert isinstance(output, list)


@pytest.mark.parametrize("available_backend", list(SigmAIQBackend.display_available_backends().keys()))
def test_get_output_formats(available_backend):
    """Tests classmethod get_backend_output_formats()"""
    backend_obj = SigmAIQBackend(backend=available_backend).create_backend()
    formats = backend_obj.get_backend_output_formats()
    assert isinstance(formats, dict)


def test_create_all_and_translate(sigma_rule):
    """Tests classmethod create_all_and_translate_all."""
    output = SigmAIQBackend.create_all_and_translate(sigma_rule)
    # ensure we have as many backends as we expect
    assert len(output.keys()) == len(SigmAIQBackend.display_available_backends().keys())
