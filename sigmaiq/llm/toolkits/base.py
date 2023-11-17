# stdlib
from typing import Optional, Dict, Any, Type, Union
import json
from json import JSONDecodeError

# langchain
from langchain.agents.agent import AgentExecutor
from langchain.agents.format_scratchpad import format_to_openai_function_messages
from langchain.agents.output_parsers import OpenAIFunctionsAgentOutputParser
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.tools.render import format_tool_to_openai_function

# langchain typing
from langchain.schema import (
    AgentAction,
    AgentFinish,
    OutputParserException,
)
from langchain.schema.vectorstore import VectorStore
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.agent import AgentActionMessageLog
from langchain.schema.messages import (
    AIMessage,
    BaseMessage,
)

# sigmaiq
from sigmaiq.llm.toolkits.sigma_toolkit import SigmaToolkit
from sigmaiq.llm.toolkits.prompts import SIGMA_AGENT_PROMPT


def create_sigma_agent(
    agent_llm: BaseLanguageModel = ChatOpenAI(model="gpt-3.5-turbo"),
    rule_creation_llm: BaseLanguageModel = ChatOpenAI(model="gpt-3.5-turbo"),
    sigma_vectorstore: VectorStore = None,
    toolkit: Type[SigmaToolkit] = SigmaToolkit,
    prompt: Optional[ChatPromptTemplate] = SIGMA_AGENT_PROMPT,
    verbose: bool = False,
    return_intermediate_steps: bool = False,
    agent_executor_kwargs: Optional[Dict[str, Any]] = None,
) -> AgentExecutor:
    """Construct a Sigma agent from an LLM and tools.

    Args:
        agent_llm (BaseLanguageModel, optional): The LLM to use for the agent. Defaults to ChatOpenAI(model="gpt-3.5-turbo").
        rule_creation_llm (BaseLanguageModel, optional): The LLM to use for the rule creation tool. Defaults to ChatOpenAI(model="gpt-3.5-turbo").
        sigma_vectorstore (VectorStore, optional): The vectorstore containing Sigma rules to use for the agent. Defaults to None.
        toolkit (Type[SigmaToolkit], optional): The toolkit to use for the agent. Defaults to SigmaToolkit.
        prompt (Optional[ChatPromptTemplate], optional): The prompt to use for the agent. Defaults to SIGMA_AGENT_PROMPT.
        verbose (bool, optional): Whether to print verbose output. Defaults to False.
        return_intermediate_steps (bool, optional): Whether to return intermediate steps. Defaults to False.
        agent_executor_kwargs (Optional[Dict[str, Any]], optional): Additional kwargs to pass to the AgentExecutor. Defaults to None.

    Returns:
        AgentExecutor: Returns a callable AgentExecutor object. Either you can call it or use run method with the query to get the response
    """  # noqa: E501

    # Get Sigma Tools from the SigmaToolkit. Init with sigma vectorstore and rule creation llm
    tools = toolkit(sigmadb=sigma_vectorstore, rule_creation_llm=rule_creation_llm).get_tools()

    # Create OpenAI Function for each tool for the agent LLM, so we can create an OpenAI Function AgentExecutor
    llm_with_tools = agent_llm.bind(functions=[format_tool_to_openai_function(t) for t in tools])

    # Create the agent
    agent = (
        {
            "input": lambda x: x["input"],
            "agent_scratchpad": lambda x: format_to_openai_function_messages(x["intermediate_steps"]),
        }
        | prompt
        | llm_with_tools
        | CustomOpenAIFunctionsAgentOutputParser()
    )

    # Create and return the AgentExecutor
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=verbose,
        return_intermediate_steps=return_intermediate_steps,
        handle_parsing_errors=True,
        **(agent_executor_kwargs or {}))

    return agent_executor


class CustomOpenAIFunctionsAgentOutputParser(OpenAIFunctionsAgentOutputParser):
    """Custom OpenAIFunctionsAgentOutputParser to overcome the JSON parsing error on some agent
    intermediate step inputs. This occurs because the `json.load()` method needs the arg `strict=False` to
parse the JSON. This is a hacky way to do this, but it works for now.
    """
    # Override
    @staticmethod
    def _parse_ai_message(message: BaseMessage) -> Union[AgentAction, AgentFinish]:
        """Parse an AI message."""
        if not isinstance(message, AIMessage):
            raise TypeError(f"Expected an AI message got {type(message)}")

        function_call = message.additional_kwargs.get("function_call", {})

        if function_call:
            function_name = function_call["name"]
            try:
                _tool_input = json.loads(function_call["arguments"].strip(), strict=False)  # HACK
            except JSONDecodeError:
                raise OutputParserException(
                    f"Could not parse tool input: {function_call} because "
                    f"the `arguments` is not valid JSON."
                )

            # HACK HACK HACK:
            # The code that encodes tool input into Open AI uses a special variable
            # name called `__arg1` to handle old style tools that do not expose a
            # schema and expect a single string argument as an input.
            # We unpack the argument here if it exists.
            # Open AI does not support passing in a JSON array as an argument.
            if "__arg1" in _tool_input:
                tool_input = _tool_input["__arg1"]
            else:
                tool_input = _tool_input

            content_msg = f"responded: {message.content}\n" if message.content else "\n"
            log = f"\nInvoking: `{function_name}` with `{tool_input}`\n{content_msg}\n"
            return AgentActionMessageLog(
                tool=function_name,
                tool_input=tool_input,
                log=log,
                message_log=[message],
            )

        return AgentFinish(
            return_values={"output": message.content}, log=str(message.content)
        )
