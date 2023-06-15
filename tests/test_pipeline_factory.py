import pytest
from sigmaiq.sigmaiq_pipeline_factory import SigmAIQPipelineResolver, SigmAIQPipeline
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from sigmaiq.exceptions import InvalidCustomFieldMapping, InvalidSigmAIQPipeline


def test_pipeline_factory_from_processing_pipeline():
    """Tests supplying basic processing pipeline to factory"""
    assert SigmAIQPipeline(
        processing_pipeline=ProcessingPipeline(
            name="test",
            priority=10,
            items=[
                ProcessingItem(
                    identifier="test_id",
                    transformation=FieldMappingTransformation({"FieldA": "FieldB"}))
            ]
        )
    ).create_pipeline().name == "test"


@pytest.mark.parametrize(
    "available_pipeline",
    list(SigmAIQPipeline.display_available_pipelines().keys())
)
def test_pipeline_factory_from_valid(available_pipeline):
    """Tests creating all available pipelines with pipeline factory."""
    pipeline = SigmAIQPipeline(processing_pipeline=available_pipeline).create_pipeline()
    assert isinstance(pipeline, ProcessingPipeline)


def test_pipeline_factory_from_invalid_str():
    """Tests creating pipeline with an invalid name (str) for a pipeline not defined in availale_pipelines."""
    with pytest.raises(InvalidSigmAIQPipeline,
                       match="Provided processing_pipeline str invalid_pipeline_name not in list of available pipelines"):
        SigmAIQPipeline(
            processing_pipeline="invalid_pipeline_name"
        ).create_pipeline()


def test_pipeline_factory_no_pipeline():
    """Tests when None or null vars are passed to the pipeline factory."""
    """Tests when no pipeline is given to the processing pipeline factory"""
    with pytest.raises(ValueError,
                       match="Please provide a valid processing pipeline value to processing_pipeline"):
        SigmAIQPipeline(processing_pipeline=None)


def test_pipeline_factory_from_callable():
    """Tests using a callable that returns a ProcessingPipeline with the factory."""

    def pipeline_callable():
        return ProcessingPipeline(
            name="test",
            priority=10,
            items=[
                ProcessingItem(
                    identifier="test_id",
                    transformation=FieldMappingTransformation({"FieldA": "FieldB"}))
            ]
        )

    assert SigmAIQPipeline(
        processing_pipeline=pipeline_callable
    ).create_pipeline().name == "test"


def test_pipeline_factory_from_invalid_callable():
    """Tests using a callable that does not return a valid type/value with the factory."""

    def pipeline_callable():
        return True

    with pytest.raises(TypeError,
                       match="Invalid processing_pipeline, "
                             "or invalid object returned from callable passed as processing_pipeline"):
        SigmAIQPipeline(processing_pipeline=pipeline_callable).create_pipeline()


def test_pipeline_factory_from_fieldmapping():
    """Tests classmethod for creating new pipeline from field mapping dict"""
    pipeline = SigmAIQPipeline.from_fieldmap(fieldmapping={"FieldA": "FieldB"},
                                             priority=10).create_pipeline()
    assert pipeline.items[0].transformation.mapping == {'FieldA': 'FieldB'}


def test_pipeline_factory_from_fieldmapping_empty():
    """Test when an empty field mapping is passed to the classmethod from_fieldmap()"""
    with pytest.raises(InvalidCustomFieldMapping,
                       match="The provided field_mappings is empty or None."):
        SigmAIQPipeline.from_fieldmap(fieldmapping={},
                                      priority=10).create_pipeline()


@pytest.mark.parametrize(
    "oob_priority",
    [-5, 105, None, "string"],
    ids=["less_than_0", "greater_than_100", "None", "a_string"]
)
def test_pipeline_factory_from_fieldmapping_priority_oob(oob_priority):
    """Tests all possible combinations of out-of-bounds or invalid values for the priority argument in the classmethod
    from_fieldmap()
    """
    if isinstance(oob_priority, str):
        with pytest.raises(TypeError, match="custom_field_mappings_priority must be of type `int`"):
            SigmAIQPipeline.from_fieldmap(fieldmapping={"FieldA": "FieldB"},
                                          priority=oob_priority).create_pipeline()
    else:
        pipeline = SigmAIQPipeline.from_fieldmap(fieldmapping={"FieldA": "FieldB"},
                                                 priority=oob_priority).create_pipeline()
        if oob_priority is None or oob_priority < 0:
            assert pipeline.priority == 0
        elif oob_priority > 100:
            assert pipeline.priority == 100


def test_pipeline_factory_invalid_name():
    with pytest.raises(TypeError,
                       match="'name' given for new fieldmapping pipeline must be of type str"):
        SigmAIQPipeline.from_fieldmap(
            {'fieldA': 'fieldB'},
            name=0
        )


def test_pipeline_factory_from_invalid_fieldmapping():
    """Tests valid keys but invalid values in the custom field mapping passed to the from_fieldmap() classmethod."""
    with pytest.raises(TypeError,
                       match="fieldmappings must be of type 'dict' with str keys and values or None"):
        SigmAIQPipeline.from_fieldmap(
            {"FieldA": 5}
        )


def test_pipeline_factory_resolver():
    """Tests creating a ProcessingPipeline with the resolver."""
    assert SigmAIQPipelineResolver(
        processing_pipelines=[
            ProcessingPipeline(
                name="test1",
                priority=10,
                items=[
                    ProcessingItem(
                        identifier="test_id1",
                        transformation=FieldMappingTransformation({"FieldA": "FieldB"}))
                ]
            ),
            ProcessingPipeline(
                name="test2",
                priority=10,
                items=[
                    ProcessingItem(
                        identifier="test_id2",
                        transformation=FieldMappingTransformation({"FieldA": "FieldB"}))
                ]
            )
        ]
    ).process_pipelines().items[0].identifier == "test_id1"


def test_pipeline_factory_resolver_invalid_pipeline():
    """Tests the resolver when passed an invalid pipeline."""
    with pytest.raises(TypeError,
                       match="processing_pipelines is not of type list or set"):
        SigmAIQPipelineResolver(processing_pipelines="invalid_item")


def test_pipeline_factory_resolver_no_pipelines():
    """Tests empty pipelines list passed to resolver"""
    with pytest.raises(ValueError,
                       match="processing_pipelines is empty or None"):
        SigmAIQPipelineResolver(processing_pipelines=[]).process_pipelines()
