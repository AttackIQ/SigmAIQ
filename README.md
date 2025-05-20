<div align="center">
    <a href="https://www.attackiq.com" target="_blank">
        <img src="https://www.attackiq.com/wp-content/uploads/2021/10/col-dflt.png" height="300" alt="AttackIQ">
    </a>
</div>
<h1 align="center">SigmAIQ: pySigma Wrapper & Utils</h1>

![Tests](https://github.com/AttackIQ/SigmAIQ/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/slincoln-aiq/f6d72f7ec2b300546a114fd80d371f7e/raw/slincoln-aiq-SigmAIQ.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)
![PyPI version](https://badge.fury.io/py/sigmaiq.svg)
![Python versions](https://img.shields.io/pypi/pyversions/sigmaiq.svg)
![pySigma version](https://img.shields.io/badge/pySigma-%3E%3D0.11.17-blue)
![License](https://img.shields.io/github/license/AttackIQ/SigmAIQ.svg)

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Project Status](#project-status)
- [LLM Support](#llm-support)
- [Installation \& Usage](#installation--usage)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage Quickstart](#usage-quickstart)
  - [Usage Examples](#usage-examples)
- [Supported Options](#supported-options)
  - [Backends](#backends-1)
  - [Pipelines](#pipelines-1)
- [Contributing](#contributing)
- [License](#license)
- [Maintainers](#maintainers)

# Introduction

SigmAIQ is a wrapper for [pySigma](https://github.com/SigmaHQ/pySigma) and pySigma backends & pipelines. It allows
detection engineers to easily convert Sigma rules and rule collections to SIEM/product queries without having to worry
about the overhead of ensuring the correct pipelines and output formats are used by each pySigma supported backend.
SigmAIQ also contains custom pipelines and output formats for various backends that are not found in the original
backend
source code. If you don't see a backend that's currently supported, please consider contributing to the Sigma/pySigma
community by making it with
this [pySigma Cookiecutter Template](https://github.com/SigmaHQ/cookiecutter-pySigma-backend)

In addition, SigmAIQ contains pySigma related tools and scripts, including easy
Sigma rule searching, LLM support, an automatic rule creation from IOCs.

This library is currently maintained by:

* [Stephen Lincoln](https://github.com/slincoln-aiq) via [AttackIQ](https://github.com/AttackIQ)

# Project Status

SigmAIQ is currently in pre-release status. It is a constant work-in-progress and bugs may be encountered. Please report any issues [here](https://github.com/AttackIQ/SigmAIQ/issues/new).

Feature requests are always welcome! pySigma tools/utils are currently not in the pre-release version,
and will be added in future releases.

# LLM Support
For LLM usage, see the [LLM README](sigmaiq/llm/README.md)

# Installation & Usage

## Requirements
- Python 3.9+
- pip, pipenv, or poetry

## Installation

SigmAIQ can be installed with your favorite package manager:

```
pip install sigmaiq
pipenv install sigmaiq
poetry add sigmaiq
```

To install the LLM dependencies, use the `llm` extra:

```
pip install sigmaiq[llm]
pipenv install sigmaiq[llm]
poetry add sigmaiq[llm]
```

## Usage Quickstart

Create a backend from the list of available backends, then give a valid Sigma rule to convert to a query. You
can find the list of available backends in this README, or `SigmAIQBackend.display_available_backends()`.

```python
from sigmaiq import SigmAIQBackend

sigma_rule = """
    title: Test Rule
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: mimikatz.exe
        condition: sel
"""

# Create backend
backend = SigmAIQBackend(backend="microsoft365defender").create_backend()

# Convert Rule or Collection
output = backend.translate(sigma_rule)
print(output)
```

Output:

```
['DeviceProcessEvents
| where ProcessCommandLine =~ "mimikatz.exe"']
```

Although you _can_ pass a SigmaRule or SigmaCollection object to `translate()` like you would to `convert()`
or `convert_rule()` for a typical pySigma backend, there is no need with SigmAIQ. As long as a valid Sigma rule is given
as a YAML str or dictionary (or list of), SigmAIQ will take care of it for you.

## Usage Examples

### Backends

Typical usage will be using the `SigmAIQBackend` class from `sigmaiq` to create a
customized pySigma backend, then use `translate()` to convert a SigmaRule or SigmaCollection to a query:

```python
from sigmaiq import SigmAIQBackend
from sigma.rule import SigmaRule

sigma_rule = SigmaRule.from_yaml(
    """
    title: Test Rule
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: mimikatz.exe
        condition: sel
    """
)

backend = SigmAIQBackend(backend="splunk").create_backend()
print(backend.translate(sigma_rule))
```

Output:
`['CommandLine="mimikatz.exe"']`

#### Specifying Output Formats

Passing the `output_format` arg will use an original output specified by the original backend, or a custom format
implemented by SigmAIQ. You can find information about output formats specific to each backend
via `SigmAIQBackend.display_backends_and_outputs()`The necessary processing pipelines are automatically
applied, even if the original pySigma backend does not automatically apply it:

```python
from sigmaiq import SigmAIQBackend
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend

sigma_rule = SigmaRule.from_yaml(
    """
    title: Test Rule
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: mimikatz.exe
        condition: sel
    """
)
# Raises sigma.exceptions.SigmaFeatureNotSupportedByBackendError
orig_backend = SplunkBackend()
print("Original Backend:")
try:
    print(orig_backend.convert_rule(sigma_rule, output_format="data_model"))
except Exception as exc:
    print(exc)
print("\n")

# Necessary pipeline for output_format automatically applied
print("SigmAIQ Backend:")
sigmaiq_backend = SigmAIQBackend(backend="splunk", output_format="data_model").create_backend()
print(sigmaiq_backend.translate(sigma_rule))
```

Output:

```
Original Backend:
No data model specified by processing pipeline

SigmAIQ Backend:
['| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) 
as lastTime from datamodel=Endpoint.Processes where Processes.process="mimikatz.exe" by Processes.process 
Processes.dest Processes.process_current_directory Processes.process_path Processes.process_integrity_level 
Processes.parent_process Processes.parent_process_path Processes.parent_process_guid Processes.parent_process_id 
Processes.process_guid Processes.process_id Processes.user | `drop_dm_object_name(Processes)` 
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) | convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime) ']
```

### Pipelines

#### Specifying Pipelines

You can specify a specific pipeline to be applied to the SigmaRule by passing it to the backend factory. Generally, you
want to only apply pipelines to a backend meant for that specific backend. You can use a name of a pipeline as defined
in `SigmAIQPipeline.display_available_pipelines()`, or pass any pySigma ProcessingPipeline object. The
pipeline can be passed directory to `SigmAIQPipeline`, or created with `SigmAIQPipeline`.

```python
from sigmaiq import SigmAIQBackend, SigmAIQPipeline

# Directly to backend
backend = SigmAIQBackend(backend="elasticsearch",
                         processing_pipeline="ecs_zeek_beats").create_backend()

# Create pipeline first, then pass to backend
pipeline = SigmAIQPipeline(processing_pipeline="ecs_zeek_beats").create_pipeline()
backend = SigmAIQBackend(backend="elasticsearch",
                         processing_pipeline=pipeline).create_backend()
```

#### Combining Multiple Pipelines

The `SigmAIQPipelineResolver` class automates combining multiple pipelines together via
pySigma's `ProcessingPipelineResolver` class. This results in a single ProcessingPipeline object that are applied in
order of priority of each ProcessingPipeline's priority. You can pass any named available pipeline, ProcessingPipeline
object, or callable that returns any valid combination of these two types:

```python
from sigmaiq import SigmAIQPipelineResolver
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.sentinelone import sentinelone_pipeline

# ProcessingPipeline Object
proc_pipeline_obj = sysmon_pipeline()

# Available Pipeline Name
pipeline_named = "splunk_windows"

my_pipelines = [sysmon_pipeline(),  # ProcessingPipeline type
                "splunk_windows",  # Available pipeline name
                sentinelone_pipeline  # Callable that returns a ProcessingPipeline type
                ]

my_pipeline = SigmAIQPipelineResolver(processing_pipelines=my_pipelines).process_pipelines(
    name="My New Optional Pipeline Name")

print(f"Created single new pipeline from {len(my_pipelines)} pipelines.")
print(f"New pipeline '{my_pipeline.name}' contains {len(my_pipeline.items)} ProcessingItems.")
```

Output:

```
Created single new pipeline from 3 pipelines.
New pipeline 'My New Optional Pipeline Name' contains 103 ProcessingItems.
```

#### Custom Fieldmappings

A dictionary can be used to create a custom fieldmappings pipeline on the fly. Each key should be the original
fieldname, with each value being a new fieldname or list of new fieldnames:

```python
from sigmaiq import SigmAIQPipeline
from sigma.rule import SigmaRule

sigma_rule = SigmaRule.from_yaml(
    """
    title: Test Rule
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: mimikatz.exe
        condition: sel
    """
)

custom_fieldmap = {'CommandLine': 'NewCommandLineField'}
custom_pipeline = SigmAIQPipeline.from_fieldmap(custom_fieldmap).create_pipeline()
print(f"Original Fieldname: {list(sigma_rule.detection.detections.values())[0].detection_items[0].field}")
custom_pipeline.apply(sigma_rule)
print(f"New Fieldname: {list(sigma_rule.detection.detections.values())[0].detection_items[0].field}")
```

Output:

```
Original Fieldname: CommandLine
New Fieldname: NewCommandLineField
```

### All-In-One Conversion

The `create_all_and_translate()` method for the backend factory will automatically create backends for all possible
available backends, and create queries for all possible pipelines & output formats for each backend.
If `show_errors=False` (default), any invalid queries due to pipeline errors, such as unsupported fields, will be left
out of the results dictionary:

```python
from sigmaiq import SigmAIQBackend
from sigma.rule import SigmaRule
from pprint import pprint

sigma_rule = SigmaRule.from_yaml(
    """
    title: Test Rule
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: mimikatz.exe
        condition: sel
    """
)

output = SigmAIQBackend.create_all_and_translate(sigma_rule)
pprint(output)
```

Output:

{backend: {pipeline: {output_format: query} } }

```
{'carbonblack': {'carbonblack': {'default': ['os_type:windows '
                                             'cmdline:mimikatz.exe'],
                                 'json': [{'description': None,
                                           'id': None,
                                           'query': 'os_type:windows '
                                                    'cmdline:mimikatz.exe',
                                           'title': 'Test Rule'}]},
                 'carbonblack_enterprise': {'default': ['device_os:WINDOWS '
                                                        'process_cmdline:mimikatz.exe'],
                                            'json': [{'description': None,
                                                      'id': None,
                                                      'query': 'device_os:WINDOWS '
                                                               'process_cmdline:mimikatz.exe',
                                                      'title': 'Test Rule'}]}},
 'crowdstrike_splunk': {'crowdstrike': {'default': ['event_simpleName="ProcessRollup2" '
                                                    'CommandLine="mimikatz.exe"']}},
 'crowdstrike_logscale': {'crowdstrike': {'default': ['event_simpleName="ProcessRollup2" '
                                                    'CommandLine="mimikatz.exe"']}},
 'elasticsearch': {'ecs_windows': {'default': ['process.command_line:mimikatz.exe'],
 ...
```

# Supported Options

## Backends

### Available Backends

| Backend Option          | Description                                                           | Associated Pipelines                                                                                 | Default Pipeline    |
| ----------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------- |
| carbonblack             | Carbon Black EDR                                                      | carbonblack<br>carbonblack_enterprise                                                                | carbonblack         |
| cortexxdr               | Palo Alto Cortex XDR                                                  | cortexxdr                                                                                            | cortexxdr           |
| crowdstrike_splunk      | Crowdstrike FDR Splunk Query                                          | crowdstrike_fdr                                                                                      | crowdstrike_fdr     |
| crowdstrike_logscale    | Crowdstrike Logscale Query                                            | crowdstrike_falcon                                                                                   | crowdstrike_falcon  |
| elasticsearch           | Elastic Elasticsearch SIEM                                            | ecs_windows<br>ecs_kubernetes<br>ecs_windows_old<br>ecs_zeek_beats<br>ecs_zeek_corelight<br>zeek_raw | ecs_windows         |
| insightidr              | Rapid7 InsightIDR SIEM                                                | insightidr                                                                                           | insightidr          |
| loki                    | Grafana Loki LogQL SIEM                                               | loki_grafana_logfmt<br>loki_promtail_sysmon<br>loki_okta_system_log                                  | loki_grafana_logfmt |
| microsoft_xdr           | Microsoft XDR Advanced Hunting Query (KQL) (Defender, Office365, etc) | microsoft_xdr                                                                                        | microsoft_xdr       |
| microsoft_sentinel_asim | Microsoft Sentinel ASIM Query (KQL)                                   | sentinel_asim                                                                                        | sentinel_asim       |
| microsoft_azure_monitor | Microsoft Azure Monitor Query (KQL)                                   | azure_monitor                                                                                        | azure_monitor       |
| netwitness              | Netwitness Query                                                      | netwitness_windows                                                                                   | netwitness_windows  |
| opensearch              | OpenSearch Lucene                                                     | ecs_windows<br>ecs_windows_old<br>ecs_zeek_beats<br>ecs_zeek_corelight<br>zeek_raw                   | ecs_windows         |
| qradar                  | IBM QRadar                                                            | qradar_fields<br>qradar_payload                                                                      | qradar_fields       |
| secops                  | Google SecOps (Chronicle)                                             | secops_udm                                                                                           | secops_udm          |
| sentinelone             | SentinelOne EDR                                                       | sentinelone                                                                                          | sentinelone         |
| splunk                  | Splunk SIEM                                                           | splunk_windows<br>splunk_wineventlog<br>splunk_windows_sysmon_acc<br>splunk_cim_dm                   | splunk_windows      |
| sigma                   | Original YAML/JSON Sigma Rule Output                                  | sigma_default                                                                                        | sigma_default       |
| stix                    | STIX 2.0 & STIX Shifter Queries                                       | stix_2_0<br>stix_shifter                                                                             | stix_2_0            |


### Backend Output Formats

| Backend Option          | Output Format Option                                                    | Description                                                                                                                                                                                                                                                   |
| ----------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| carbonblack             | default<br>json                                                         | Plain CarbonBlack queries<br>CarbonBlack JSON query                                                                                                                                                                                                           |
| cortexxdr               | default<br>json                                                         | Plain CortexXDR queries<br>json output format                                                                                                                                                                                                                 |
| crowdstrike_splunk      | default                                                                 | Plain SPL queries                                                                                                                                                                                                                                             |
| crowdstrike_logscale    | default                                                                 | CrowdStrike LogScale queries                                                                                                                                                                                                                                  |
| elasticsearch           | default<br>kibana_ndjson<br>dsl_lucene<br>siem_rule<br>siem_rule_ndjson | Plain Elasticsearch Lucene queries<br>Kibana NDJSON import file with Lucene queries<br>Elasticsearch query DSL with embedded Lucene queries<br>Elasticsearch query DSL as SIEM Rules in JSON Format<br>Elasticsearch query DSL as SIEM Rules in NDJSON Format |
| insightidr              | default<br>leql_advanced_search<br>leql_detection_definition            | Simple log search query mode<br>Advanced Log Entry Query Language (LEQL) queries<br>LEQL format roughly matching the 'Rule Logic' tab in ABA detection rule definition                                                                                        |
| loki                    | default<br>ruler                                                        | Plain Loki queries<br>Loki 'ruler' output format for generating alerts                                                                                                                                                                                        |
| microsoft_xdr           | default                                                                 | Kusto Query Language search strings                                                                                                                                                                                                                           |
| microsoft_sentinel_asim | default                                                                 | Kusto Query Language search strings                                                                                                                                                                                                                           |
| microsoft_azure_monitor | default                                                                 | Kusto Query Language search strings                                                                                                                                                                                                                           |
| netwitness              | default                                                                 | Plain netwitness queries                                                                                                                                                                                                                                      |
| opensearch              | default<br>dashboards_ndjson<br>monitor_rule<br>dsl_lucene              | Plain OpenSearch Lucene queries<br>OpenSearch Dashboards NDJSON import file with Lucene queries<br>OpenSearch monitor rule with embedded Lucene query<br>OpenSearch query DSL with embedded Lucene queries                                                    |
| qradar                  | default                                                                 | Plain QRadar queries                                                                                                                                                                                                                                          |
| secops                  | default<br>yara_l                                                       | Plain UDM queries<br>YARA-L 2.0 Detection Rules Output Format                                                                                                                                                                                                 |
| sentinelone             | default<br>json                                                         | Plaintext<br>JSON format                                                                                                                                                                                                                                      |
| splunk                  | default<br>savedsearches<br>data_model<br>stanza                        | Plain SPL queries<br>Plain SPL in a savedsearches.conf file<br>Data model queries with tstats<br>Enterprise Security savedsearches.conf stanza                                                                                                                |
| sigma                   | default<br>yaml<br>json                                                 | Default output format<br>Default Sigma Rule output format<br>JSON style Sigma Rule Output                                                                                                                                                                     |
| stix                    | default                                                                 | Plain stix queries                                                                                                                                                                                                                                            |

## Pipelines

### Available Named Pipelines

| Pipeline Option           | Description                                                                                                                                 | Display Name                     |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| splunk_wineventlog        | SigmAIQ Custom combined windows_audit and splunk_windows pipelines to convert Sysmon fields to Windows Event Log fields for Splunk searches | Splunk WinEventLog               |
| carbonblack               | Uses Carbon Black EDR field mappings                                                                                                        | CB                               |
| cortexxdr                 | Uses Palo Alto Cortex XDR field mappings                                                                                                    | Palo Alto Cortex XDR             |
| carbonblack_enterprise    | Uses Carbon Black Enterprise EDR field mappings                                                                                             | CB                               |
| crowdstrike_fdr           | Crowdstrike FDR Splunk Mappings                                                                                                             | CrowdStrike FDR SPL              |
| crowdstrike_falcon        | Crowdstrike Falcon Logscale Mappings                                                                                                        | CrowdStrike Falcon Logscale      |
| ecs_kubernetes            | Elastic Common Schema (ECS) Kubernetes audit log mappings                                                                                   | ECS Kubernetes                   |
| ecs_windows               | Elastic Common Schema (ECS) Windows log mappings from Winlogbeat from version 7                                                             | ECS Winlogbeat                   |
| ecs_windows_old           | Elastic Common Schema (ECS) Windows log mappings from Winlogbeat up to version 6                                                            | ESC Winlogbeat (<= v6.x)         |
| ecs_zeek_beats            | Elastic Common Schema (ECS) for Zeek using filebeat >= 7.6.1                                                                                | ECS Zeek (Elastic)               |
| ecs_zeek_corelight        | Elastic Common Schema (ECS) mapping from Corelight                                                                                          | ESC Zeek (Corelight)             |
| zeek_raw                  | Zeek raw JSON field naming                                                                                                                  | Zeek Raw JSON                    |
| insightidr                | InsightIDR Log Entry Query Language (LEQL) Transformations                                                                                  | InsightIDR LEQL                  |
| loki_grafana_logfmt       | Converts field names to logfmt labels used by Grafana                                                                                       | Logfmt Labels                    |
| loki_promtail_sysmon      | Parse and adjust field names for Windows sysmon data produced by promtail                                                                   | WinSysmon Promtail               |
| loki_okta_system_log      | Parse the Okta System Log event json, adjusting field-names appropriately                                                                   | Okta System Event                |
| microsoft_xdr             | Mappings for Sysmon -> XDR Advanced Hunting Query Table Schema                                                                              | Microsoft XDR KustoQL            |
| sentinel_asim             | Mappings for Sysmon -> Sentinel ASIM Query Table Schema                                                                                     | Sentinel ASIM KustoQL            |
| azure_monitor             | Mappings for Sysmon -> Azure Monitor Query Table Schema                                                                                     | Azure Monitor KustoQL            |
| netwitness_windows        | Netwitness Windows log mappings                                                                                                             | Netwitness Windows               |
| qradar_fields             | Supports only the Sigma fields in the Field Mapping                                                                                         | Sigma Fields                     |
| qradar_payload            | Uses UTF8(payload) instead of fields unsupported by the Field Mapping.                                                                      | UTF8(payload) (Non-Sigma Fields) |
| sigma_default             | Empty ProcessingPipeline placeholder                                                                                                        | Sigma                            |
| secops_udm                | Mappings for Google SecOps (Chronicle) UDM                                                                                                  | Google SecOps UDM                |
| sentinelone               | Mappings for SentinelOne Deep Visibility Queries                                                                                            | SentinelOne Deep Visibility      |
| splunk_windows            | Splunk Query, Windows Mappings                                                                                                              | Splunk Query (Windows)           |
| splunk_windows_sysmon_acc | Splunk Windows Sysmon search acceleration keywords                                                                                          | Splunk Query (Sysmon)            |
| splunk_cim_dm             | Splunk Datamodel Field Mappings                                                                                                             | Splunk Datamodel Query           |
| stix_2_0                  | STIX 2.0 Mappings                                                                                                                           | STIX 2.0                         |
| stix_shifter              | STIX Shifter Mappings                                                                                                                       | STIX Shifter                     |
| windows_sysmon            | Sysmon for Windows                                                                                                                          | Sysmon                           |
| windows_audit             | Windows Event Logs                                                                                                                          | Windows Event Logs               |
| windows_logsource         | Windows Logs, General                                                                                                                       | Windows Logs, General            |

# Contributing

We welcome contributions to SigmAIQ! Here's how you can contribute:

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes and commit them with a clear commit message
4. Push your changes to your fork
5. Submit a pull request to the main repository

Please ensure your code adheres to the project's coding standards and includes appropriate tests.

# License

This project is licensed under the [LGPL License](LICENSE).

# Maintainers

This library is currently maintained by:

* [Stephen Lincoln](https://github.com/slincoln-aiq) via [AttackIQ](https://github.com/AttackIQ)
