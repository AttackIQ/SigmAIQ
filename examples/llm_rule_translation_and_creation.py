# %% This example will demonstrate how to create a Sigma langchain agent chatbot, which can perform various tasks like
# %% automatically translate a rule for you, and create new rules from a users input.

# %% Import required SigmAIQ classes and functions
from sigmaiq.llm.toolkits.base import create_sigma_agent
from sigmaiq.llm.base import SigmaLLM

# %% Ensure we have our Sigma vector store setup with our base LLM class
sigma_llm = SigmaLLM()

try:
    sigma_llm.load_sigma_vectordb()
except Exception as e:
    print(e)
    print("Creating new Sigma VectorDB")
    sigma_llm.create_sigma_vectordb(save=True)

# %% Create a Sigma Agent Executor, and pass it our Sigma VectorDB
sigma_agent_executor = create_sigma_agent(sigma_vectorstore=sigma_llm.sigmadb)

# %% RULE TRANSLATION
# %% Have the agent automatically translate a Sigma rule to a Splunk query with the splunk_cim_dm pipeline

sigma_rule = r"""
title: whoami Command
description: Detects a basic whoami commandline execution
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        - CommandLine|contains: 'whoami.exe'
    condition: selection1
"""

user_input = ("Translate the following Sigma rule to a Splunk query using the 'splunk_cim_dm' pipeline: \n\n" +
              sigma_rule)

# answer = sigma_agent_executor.invoke({"input": user_input})
# print("\nRULE TRANSLATION:", end="\n\n")
#print(f"Question:\n {user_input}", end="\n\n")
#print(f"Answer: \n")
#print(answer.get('output'), end="\n\n")

# %% RULE CREATION
# %% The agent will take the user input, look up similar Sigma Rules in the Sigma vector store, then create a brand
# %% new rule based on the context of the users input and the similar Sigma Rules.

user_input = ("Create a Windows process creation Sigma Rule for certutil downloading a file "
              "from definitely-not-malware.com, then translate it to a Microsoft 365 Defender query.")

answer = sigma_agent_executor.invoke({"input": user_input})
print("\nRULE CREATION:", end="\n\n")
print(f"Question:\n {user_input}", end="\n\n")
print(f"Answer: \n")
print(answer.get('output'), end="\n\n")


