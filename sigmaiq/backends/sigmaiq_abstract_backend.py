from abc import ABC
from sigma.processing.pipeline import ProcessingPipeline
from sigmaiq.sigmaiq_pipeline_factory import SigmAIQPipeline, SigmAIQPipelineResolver
from sigma.rule import SigmaRule
from sigma.conversion.base import Backend, TextQueryBackend
from sigma.collection import SigmaCollection
from typing import Union, Dict, List
from sigmaiq.exceptions import InvalidOutputFormat


class AbstractGenericSigmAIQBackendClass(TextQueryBackend, ABC):
    """
    Abstract class for the SigmAIQBackendFactory class.

    All AIQ backends must inherit this class, as well as the specific backend class that should be used based on the
    selected pySigma backend. This way, we can still have all the functionality of a typical pySigma Backend,
    but be able to add methods and override things as needed if we need to customize things.

    For example, we add a 'custom_formats' attribute, since pySigma backends have their own dict of
    output formats defined, but we can define our own and postprocess output if we supply our own
    custom_format that doesn't appear in the dict defined in the pySigma Backend class , i.e. we want
    to take the string output from the Splunk backend, but then postprocess it and put it in a savedsearches.conf
    stanza to show to the user; this isn't available in the pySigma Splunk Backend.

    Attributes:
        custom_formats: (Dict) of any custom output formats that are not part of the parent TextBackend class 'formats'
        attribute. These should be handled by overriding the method `handle_output_format`.
        Dict should follow {'format': 'description}

        associated_pipelines: (List) of all pipelines that can/should be used with the backend. Usually, these are
        pipelines that are created alongside the backend by the backend's author. Elements in this list should be
        listed as keys in sigmaiq.sigmaiq_pipeline_factory.AVAILABLE_PIPELINES.

        default_pipeline: (str) The default pipeline name to use (as seen in AVAILABLE_PIPELINES.keys()) if no pipeline is
        provided.  Most of the time, the authors of pySigma backends will automatically apply the required pipelines,
        but some do not.
    """

    custom_formats = {}
    associated_pipelines = []
    default_pipeline = ProcessingPipeline()

    def __init__(self, processing_pipeline: ProcessingPipeline = None, output_format: str = None):
        """Initialize instance attributes.
        :param processing_pipeline: ProcessingPipeline object to apply to the SigmaRule or SigmaCollection object to
        translate. If None, no ProcessingPipelines will be applied as part of the translation process to the backend,
        but can still be manually applied outside the scope of backend translations
        :type processing_pipeline: ProcessingPipeline, optional
        :param output_format: Output format to use, typically for post-processing the SigmaRule or SigmaCollection
        translation. Each subclass implementing this class may have specific values they use to handle post-processing
        :type output_format: str
        """
        self.output_format = None
        self.custom_output_format = None
        self.processing_pipeline = self._validate_processing_pipeline(processing_pipeline or self.default_pipeline)
        self._validate_output_format(output_format)
        super().__init__(processing_pipeline=self.processing_pipeline)
        # Ensure we aren't applying a pipeline automatically applied by the backend
        if self.backend_processing_pipeline and self.processing_pipeline:
            if self.processing_pipeline.name == self.backend_processing_pipeline.name:
                self.processing_pipeline = None

    def translate(self, sigma_rule: Union[SigmaRule, SigmaCollection, List, Dict, str]):
        """Default implementation to translate a SigmaRule or SigmaCollection object into a Splunk query

        :param sigma_rule: SigmaRule, SigmaCollection, or valid YAML str/dictionary containing a valid Sigma rule
        to translate, with or without ProcessingPipelines already applied to it.
        If a ProcessingPipeline is supplied to this class on __init__, it will automatically apply to the SigmaRule.
        :type sigma_rule: Union[SigmaRule, SigmaCollection, List, Dict, str]
        :return: List of converted query/queries. In the case of a SigmaRule, the list will have one element.
        :rtype: list
        """
        # Ensure the sigma_rule is a SigmaRule or SigmaCollection object. If it's not, try to make one.
        sigma_rule = self._check_sigma_rule(sigma_rule)
        # Ensure the required pipelines have been applied to the rule, or are present in the instances
        # processing pipeline attribute. Otherwise, the conversion will most likely throw errors
        if self.associated_pipelines and self.default_pipeline:
            _ = self._ensure_proper_pipelines(sigma_rule)
        # Next
        if isinstance(sigma_rule, SigmaRule):
            output = self._translate_rule(sigma_rule)
        else:
            output = self._translate_collection(sigma_rule)
        if self.custom_output_format:
            output = self.handle_output_format(sigma_rule, output)
        return output

    def handle_output_format(self, sigma_rule: Union[SigmaCollection, SigmaRule], output: List[str]):
        """Postprocessing of output of rule converted by backend for self.custom_output_format"""
        if self.custom_output_format:
            pass
        else:
            pass
        return output

    def _translate_rule(self, sigma_rule):
        return self.convert_rule(sigma_rule, output_format=self.output_format)

    def _translate_collection(self, sigma_collection):
        output = self.convert(sigma_collection, output_format=self.output_format)
        if not isinstance(output, list):
            output = [output]
        return output

    def _check_sigma_rule(self, sigma_rule: Union[SigmaRule, SigmaCollection, List, Dict, str]) -> \
            Union[SigmaRule, SigmaCollection]:
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
            return SigmaCollection([self._check_sigma_rule(s) for s in sigma_rule])
        if isinstance(sigma_rule, dict):  # Create one from dict
            return SigmaRule.from_dict(sigma_rule)
        if isinstance(sigma_rule, str):  # from YAML str
            return SigmaRule.from_yaml(sigma_rule)
        raise TypeError(f"Invalid type '{type(sigma_rule)}' for `sigma_rule`. "
                        f"Use a SigmaRule, SigmaCollection, dict, str, or list of these types instead.")

    @staticmethod
    def _validate_processing_pipeline(processing_pipeline):
        if processing_pipeline and not isinstance(processing_pipeline, ProcessingPipeline):
            processing_pipeline = SigmAIQPipeline(processing_pipeline).create_pipeline()
        return processing_pipeline

    def _validate_output_format(self, output_format):
        if output_format:
            if output_format in self.custom_formats.keys():
                self.custom_output_format = output_format
            if output_format in self.formats.keys():
                self.output_format = output_format
            if not self.output_format and not self.custom_output_format:
                raise InvalidOutputFormat(f"Invalid output_format {output_format} for Backend {type(self).__name__}")
            if not self.output_format:
                self.output_format = "default"

    def get_backend_output_formats(self) -> Dict[str, str]:
        output_formats = {**self.formats, **self.custom_formats}
        if not output_formats:
            output_formats = {'default': 'Default query string output'}
        return output_formats

    def _ensure_proper_pipelines(self, sigma_obj: Union[SigmaRule, SigmaCollection]):
        """Ensures that the default pipeline is applied to SigmaRules to be converted.
        This is to avoid potential errors when converting untransformed rules.

        It will look to see if any ProcessingItems inside ProcessingPipelines of self.associated_pipelines have been
        applied to any SigmaRule detection item objects or if any ProcessingPipelines/ProcessingItems exist in
        self.process_pipeline. If not, then self.default_pipeline will automatically be added to the instances pipeline
        and applied at rule conversion time.

        :param sigma_obj:
        :type sigma_obj: Union[SigmaRule, SigmaCollection]
        """
        associated_pipelines = [
            SigmAIQPipeline(processing_pipeline=p).create_pipeline() for p in self.associated_pipelines
        ]
        set_processing_pipeline_item_ids = [x.identifier for x in
                                            self.processing_pipeline.items] if self.processing_pipeline else []

        # Check if self.processing_pipeline has the same name as any associated pipelines
        if self.processing_pipeline:
            if any(x.name == self.processing_pipeline.name for x in associated_pipelines):
                return True

        # Maybe pipelines were combined, so check if all ProcessingItems from any associated pipeline exist
        for associated_pipeline in associated_pipelines:
            if all(proc_item.identifier in set_processing_pipeline_item_ids for proc_item in associated_pipeline.items):
                return True
            # Check to see if it's automatically applied by the backend
            if associated_pipeline.name == self.backend_processing_pipeline.name:
                return True
            if isinstance(sigma_obj, SigmaRule):
                if any(proc_item.identifier in sigma_obj.applied_processing_items for proc_item in
                       associated_pipeline.items):
                    return True
            else:
                for sigma_rule in sigma_obj:
                    if any(proc_item.identifier in sigma_rule.applied_processing_items for proc_item in
                           associated_pipeline.items):
                        return True

        if not self.processing_pipeline:  # No pipeline currently
            self.processing_pipeline = SigmAIQPipeline(
                processing_pipeline=self.default_pipeline).create_pipeline()
        else:  # We have a pipeline, add the default to the beginning of it
            self.processing_pipeline = SigmAIQPipelineResolver(processing_pipelines=[
                self.default_pipeline,
                self.processing_pipeline
            ]).process_pipelines()
