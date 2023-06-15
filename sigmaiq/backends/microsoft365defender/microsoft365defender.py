from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigmaiq.backends.sigmaiq_abstract_backend import AbstractGenericSigmAIQBackendClass


class SigmAIQMicrosoft365DefenderBackend(AbstractGenericSigmAIQBackendClass, Microsoft365DefenderBackend):
    custom_formats = {}
    associated_pipelines = ['microsoft365defender']
    default_pipeline = 'microsoft365defender'

