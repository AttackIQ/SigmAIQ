from sigma.backends.elasticsearch import LuceneBackend
from sigmaiq.backends.sigmaiq_abstract_backend import AbstractGenericSigmAIQBackendClass


class SigmAIQElasticsearchBackend(AbstractGenericSigmAIQBackendClass, LuceneBackend):
    custom_formats = {}
    associated_pipelines = ['ecs_windows',
                            'ecs_windows_old',
                            'ecs_zeek_beats',
                            'ecs_zeek_corelight',
                            'zeek_raw']
    default_pipeline = "ecs_windows"

