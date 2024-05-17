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

print("\n--------\nRULE TRANSLATION\n--------\n")
# %% RULE TRANSLATION
# %% Have the agent automatically translate a Sigma rule to a Splunk query with the splunk_cim_dm pipeline
user_input = "Convert this Sigma rule to a Splunk query using the 'splunk_cim_dm' pipeline: \n\n" + \
             "title: whoami Command\n" + \
             "description: Detects a basic whoami commandline execution\n" + \
             "logsource:\n" + \
             "    product: windows\n" + \
             "    category: process_creation\n" + \
             "detection:\n" + \
             "    selection1:\n" + \
             "        - CommandLine|contains: 'whoami.exe'\n" + \
             "    condition: selection1"

answer = sigma_agent_executor.invoke({"input": user_input})
print(f"\n\nQUESTION:\n {user_input}", end="\n\n")
print("ANSWER: \n")
print(answer.get('output'), end="\n\n")

# %% RULE SEARCHING
# %% The agent will find official Sigma rules in the Sigma vector store based on the context of the users input.
print("\n--------\nRULE SEARCHING\n--------\n")

user_input = ("What Sigma Rule can detect a process creation event where the parent process is word.exe and the child "
              "process is cmd.exe?")

answer = sigma_agent_executor.invoke({"input": user_input})
print(f"QUESTION:\n {user_input}", end="\n\n")
print("ANSWER: \n")
print(answer.get('output'), end="\n\n")

# %% QUERY TO SIGMA RULE CONVERSION
# %% If you already have a query and want to convert it back to a Sigma Rule
print("\n--------\nQUERY TO SIGMA RULE \n--------\n")

user_input = """
Convert this Microsoft365Defender query into a Sigma Rule:
DeviceProcessEvents
| where ((ProcessCommandLine contains "powershell.exe -enc" or ProcessCommandLine contains "cmd.exe /c" or ProcessCommandLine contains "rundll32.exe") or (InitiatingProcessFolderPath endswith "\\explorer.exe" or InitiatingProcessFolderPath endswith "\\svchost.exe")) and (not((ProcessCommandLine contains "schtasks" or ProcessCommandLine contains "tasklist")))

"""

answer = sigma_agent_executor.invoke({"input": user_input})
print(f"\n\nQUESTION:\n {user_input}", end="\n\n")
print("ANSWER: \n")
print(answer.get('output'), end="\n\n")

# %% RULE CREATION
# %% The agent will take the user input, look up similar Sigma Rules in the Sigma vector store, then create a brand
# %% new rule based on the context of the users input and the similar Sigma Rules.
print("\n--------\nRULE CREATION\n--------\n")

user_input = ("Create a Windows process creation Sigma Rule for certutil downloading a file "
              "from definitely-not-malware.com, then translate it to a Microsoft 365 Defender query.")

answer = sigma_agent_executor.invoke({"input": user_input})
print(f"QUESTION:\n {user_input}", end="\n\n")
print("ANSWER: \n")
print(answer.get('output'), end="\n\n")


# %% RULE CREATION + TRANSLATION
# %% The agent will take the user input, look up similar Sigma Rules in the Sigma vector store, then create a brand
# %% new rule based on the context of the users input and the similar Sigma Rules. Then convert it to a M365 query
print("\n--------\nRULE CREATION + TRANSLATION\n--------\n")

user_input = ("Create a Windows process creation Sigma Rule for certutil downloading a file "
              "from definitely-not-malware.com, then translate it to a Microsoft 365 Defender query.")

answer = sigma_agent_executor.invoke({"input": user_input})
print(f"QUESTION:\n {user_input}", end="\n\n")
print("ANSWER: \n")
print(answer.get('output'), end="\n\n")
