import pytest
from unittest.mock import patch, create_autospec
from langchain.schema import AgentAction, AgentFinish, Document, AIMessage
from langchain.schema.vectorstore import VectorStore
from langchain_openai import OpenAIEmbeddings
from langchain.schema.language_model import BaseLanguageModel

from sigmaiq.llm.base import SigmaLLM
from sigmaiq.llm.toolkits.base import create_sigma_agent
from sigmaiq.llm.toolkits.sigma_toolkit import SigmaToolkit
from sigmaiq.llm.tools.create_sigma_rule import CreateSigmaRuleVectorStoreTool
from sigmaiq.llm.tools.translate_sigma_rule import TranslateSigmaRuleTool
from sigmaiq.llm.tools.find_sigma_rule import FindSigmaRuleTool
from sigmaiq.llm.tools.query_to_sigma_rule import QueryToSigmaRuleTool


class MockLLM(BaseLanguageModel):
    def invoke(self, *args, **kwargs):
        return "Mocked LLM response"

    async def ainvoke(self, *args, **kwargs):
        return """title: Detect PowerShell Execution
description: Detects PowerShell execution
status: test
author: MockLLM
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection"""

    def generate_prompt(self, *args, **kwargs):
        return "Mocked generate_prompt response"

    async def agenerate_prompt(self, *args, **kwargs):
        return "Mocked async generate_prompt response"

    def predict(self, *args, **kwargs):
        return "Mocked predict response"

    async def apredict(self, *args, **kwargs):
        return "Mocked async predict response"

    def predict_messages(self, *args, **kwargs):
        return "Mocked predict_messages response"

    async def apredict_messages(self, *args, **kwargs):
        return "Mocked async predict_messages response"


# Mock OpenAI API calls
@pytest.fixture
def mock_openai_create():
    with patch("openai.ChatCompletion.create") as mock_create:
        mock_create.return_value = {"choices": [{"message": {"content": "Mocked OpenAI response"}}]}
        yield mock_create


@pytest.fixture
def mock_openai_embeddings():
    with patch.object(OpenAIEmbeddings, "embed_documents") as mock_embed:
        mock_embed.return_value = [[0.1, 0.2, 0.3]]  # Mocked embedding
        yield mock_embed


@pytest.fixture
def mock_vector_store():
    class MockVectorStore(VectorStore):
        def add_texts(self, texts, metadatas=None, **kwargs):
            pass

        def similarity_search(self, query, k=4, **kwargs):
            return [Document(page_content="Mocked Sigma rule content")]

        async def asimilarity_search(self, query, k=4, **kwargs):
            return [Document(page_content="Mocked Sigma rule content")]

        @classmethod
        def from_texts(cls, texts, embedding, metadatas=None, **kwargs):
            return cls()

    return MockVectorStore()


def test_sigma_llm_initialization(mock_openai_embeddings):
    sigma_llm = SigmaLLM(embedding_model=OpenAIEmbeddings())
    assert sigma_llm.embedding_function is not None


def test_create_sigma_agent(mock_vector_store):
    mock_llm = MockLLM()
    agent_executor = create_sigma_agent(sigma_vectorstore=mock_vector_store, rule_creation_llm=mock_llm)
    assert agent_executor is not None
    assert hasattr(agent_executor, "run")


def test_sigma_toolkit():
    mock_vector_store = create_autospec(VectorStore)
    mock_llm = MockLLM()  # Use the MockLLM class we defined earlier
    toolkit = SigmaToolkit(sigmadb=mock_vector_store, rule_creation_llm=mock_llm)
    tools = toolkit.get_tools()
    assert len(tools) == 4
    assert any(isinstance(tool, CreateSigmaRuleVectorStoreTool) for tool in tools)
    assert any(isinstance(tool, TranslateSigmaRuleTool) for tool in tools)
    assert any(isinstance(tool, FindSigmaRuleTool) for tool in tools)
    assert any(isinstance(tool, QueryToSigmaRuleTool) for tool in tools)


@pytest.mark.asyncio
async def test_create_sigma_rule_tool(mock_openai_create, mock_vector_store):
    tool = CreateSigmaRuleVectorStoreTool(sigmadb=mock_vector_store, llm=MockLLM())
    result = await tool._arun("Create a Sigma rule for detecting PowerShell execution")
    assert isinstance(result, str)
    assert "title:" in result.lower()


@pytest.mark.asyncio
async def test_translate_sigma_rule_tool(mock_openai_create):
    tool = TranslateSigmaRuleTool()
    result = await tool._arun(sigma_rule="title: Test Rule\ndetection:\n  condition: selection", backend="splunk")
    assert isinstance(result, str)


@pytest.mark.asyncio
async def test_find_sigma_rule_tool(mock_openai_create, mock_vector_store):
    tool = FindSigmaRuleTool(sigmadb=mock_vector_store, llm=MockLLM())
    result = await tool._arun("Find a rule for detecting mimikatz")
    assert isinstance(result, str)


@pytest.mark.asyncio
async def test_query_to_sigma_rule_tool(mock_openai_create):
    tool = QueryToSigmaRuleTool(llm=MockLLM())
    result = await tool._arun(query="process_name=powershell.exe", backend="splunk")
    assert isinstance(result, str)
    assert "title:" in result.lower()


@pytest.mark.asyncio
async def test_agent_execution(mock_openai_create, mock_vector_store):
    agent_executor = create_sigma_agent(sigma_vectorstore=mock_vector_store)
    result = await agent_executor.ainvoke({"input": "Create a Sigma rule for detecting PowerShell execution"})
    assert isinstance(result, dict)
    assert "output" in result


def test_custom_openai_functions_agent_output_parser():
    from sigmaiq.llm.toolkits.base import CustomOpenAIFunctionsAgentOutputParser

    parser = CustomOpenAIFunctionsAgentOutputParser()

    # Test parsing an AgentAction
    message = AIMessage(
        content="", additional_kwargs={"function_call": {"name": "test_function", "arguments": '{"arg1": "value1"}'}}
    )
    result = parser.parse(message)
    assert isinstance(result, AgentAction)
    assert result.tool == "test_function"
    assert result.tool_input == {"arg1": "value1"}

    # Test parsing an AgentFinish
    message = AIMessage(content="Final answer")
    result = parser.parse(message)
    assert isinstance(result, AgentFinish)
    assert result.return_values == {"output": "Final answer"}

    # Test parsing a string (should raise ValueError)
    with pytest.raises(ValueError):
        parser.parse("This is a string, not an AIMessage")


# Add more tests as needed for other components and edge cases
