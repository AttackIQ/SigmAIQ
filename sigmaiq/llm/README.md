<div align="center">
    <a href="https://www.attackiq.com" target="_blank">
        <img src="https://www.attackiq.com/wp-content/uploads/2021/10/col-dflt.png" height="300" alt="AttackIQ">
    </a>
</div>
<h1 align="center">SigmAIQ: LLM</h1>


NOTE: This is an experimental feature that is under active development. It is not recommended for production use.
By default, OpenAI embeddings and LLM models (gpt-3.5-turbo) are used, which  require an OpenAI API key set in the environmental 
variable `OPENAI_API_KEY`.

## Overview
The goal of this SigmAIQ feature is to utilize the power of LLMs and Vector Databases with Sigma Rules.  
This feature uses [langchain](https://github.com/langchain-ai/langchain) and [pySigma](https://github.com/SigmaHQ/pySigma)
to utilize LLMs and Agents for Sigma Rule translation and creation.
Currently, the use cases of this feature include:
- Embedding creation and storage of Sigma Rules
- Sigma Rule similarity searching
- Agent/Bot for Sigma Rule translation and creation
- Converting backend queries to Sigma Rules

Please see the `examples` folder for use case examples.

### Embedding Creation and Storage
The `sigmaiq.llm.base.SigmaLLM` class is used to automatically download the latest Sigma Rules from the [SigmaHQ](https://github.com/SigmaHQ/sigma/releases/latest) repo. 
By default, this downloads the `sigma_core` ruleset into this projects `data` directory.  Embeddings are then created for each rule and stored in a Vector Database.
By default, `OpenAIEmbeddings` and `FAISS` are used, respectively.  The `sigmaiq.llm.base.SigmaLLM` class can be extended to use different embedding and vector database implementations.

### Sigma Rule Similarity Searching
The `sigmaiq.llm.base.SigmaLLM` class is also used to search for similar Sigma Rules using a similarity search. This does not require LLM models to be trained, as the embeddings are already created and stored in the Vector Database.
This can be a cheaper, yet less accurate option, for searching through Sigma Rules. By default, the top 3 matching rules
are returned based on the query sent to the similarity search. Other `langchain` `VectorStore` searching functionality can be used on the VectorStore as well.

### Agent/Bot for Sigma Rule Translation and Creation
A `langchain` `Agent` can be created with the `create_sigma_agent()` function in `sigmaiq.llm.toolkits.base`. 
This agent uses the tools contained in the `SigmaToolkit` class (in `sigmaiq/llm/toolkits/sigma_toolkit`) for various tasks. 
The Agent will automatically determine what tools to use based on the query sent to it, and can run different tools in succession to complete a task.

For rule translation, the Agent will automatically parse the contents of the user's query to determine what backend, pipeline, and output format
to use for the translation. The Agent will then create a `SigmAIQBackend` and translate the rule provided in the query.

For rule creation, the Agent will first look for similar Sigma Rules in the local Sigma VectorStore (from `SigmaLLM`) and return
the top 3 best matching rules. The Agent will then use these matching rules as context, in addition to the context/IOCs in the user's question, 
to create a brand new Sigma Rule! The Agent will then return the newly created Sigma Rule to the user.


#### Example Q&A
This example demonstrates how the agent can use multiple tools in succession; in this case, a Sigma Rule is first created 
based on the user's question with the rule creation tool, then the rule is translated to a Microsoft 365 Defender query with the rule translation tool.
The Sigma Rule YAML can be found retrieved in the `intermediate_steps` of the output.

QUESTION: "Create a Windows process creation Sigma Rule for certutil downloading a file from definitely-not-malware.com, then translate it to a Microsoft 365 Defender query."

ANSWER:

Intermediate Step (Rule Creation):
```yaml
title: Windows Process Creation Event with certutil.exe Downloading from definitely-not-malware.com
description: Detects a Windows process creation event where certutil.exe downloads a file from definitely-not-malware.com
references:
    - https://github.com/AttackIQ/SigmAIQ
author: SigmAIQ (AttackIQ)
date: 2022/12/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: 'definitely-not-malware.com'
    condition: selection
falsepositives:
    - Unknown
level: high
```

Final Output:

Here is the translated Microsoft 365 Defender query:

```
DeviceProcessEvents
| where FolderPath endswith "\\certutil.exe" and ProcessCommandLine contains "definitely-not-malware.com"
```


## Installation
Clone this repo, then install SigmAIQ dependencies along with the `llm` group dependencies 
with your favorite Python package manager, such as pip or poetry.

### pip
```bash
pip install -e .
pip install -r requirements/llm.txt
```

### poetry
```bash
poetry install --with llm
```


## Usage
For usage examples, please see the `examples` directory. By default, OpenAI embeddings and LLM models are used, which 
require an OpenAI API key set in the environmental variable `OPENAI_API_KEY`.


## Known Issues
- Agent parsing issues sometimes occur when invalid JSON is passed between agent steps.


## TODO
- Add example for using custom (and free) embeddings and LLM models
- Add example for using custom Vector Databases
- Add ability to easily customize prompts for tools/agents
- Sigma Rule Creation Tool without Vector Databases
- Adding metadata to Vector Database entries for advanced filtering on Sigma Rule fields
  - I.E. category, product, level, status, etc


## License
This project is licensed under the terms of the GNU LGPL, version 2.1. Please see the `LICENSE` file for full details.


## Contributing
Contributions and use cases are welcome! Please submit a PR or issue if you would like to contribute or have any questions.


## Acknowledgements
First and foremost, we'd like to acknowledge the creators, maintainers, contributors, and everyone else involved with the
[Sigma](https://github.com/SigmaHQ/sigma/) and [pySigma](https://github.com/SigmaHQ/pySigma) projects for obvious reasons.

We'd also like to acknowledge the [langchain](https://github.com/langchain-ai/langchain) project the work with making
LLMs more accessible and easier to use.  