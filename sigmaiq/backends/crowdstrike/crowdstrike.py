from sigma.backends.splunk import SplunkBackend
from sigmaiq.backends.sigmaiq_abstract_backend import AbstractGenericSigmAIQBackendClass


class SigmAIQCrowdstrikeSplunkBackend(AbstractGenericSigmAIQBackendClass, SplunkBackend):
    custom_formats = {}
    associated_pipelines = ['crowdstrike']
    default_pipeline = "crowdstrike"
    formats = {"default": SplunkBackend.formats["default"]}

