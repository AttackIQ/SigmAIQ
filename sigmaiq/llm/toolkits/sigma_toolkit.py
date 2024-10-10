# stdlib
from typing import List

# langchain
from langchain.agents.agent_toolkits.base import BaseToolkit
from langchain.tools import BaseTool

# langchain typing
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.vectorstore import VectorStore

# sigmaiq tools
from sigmaiq.llm.tools.create_sigma_rule import CreateSigmaRuleVectorStoreTool
from sigmaiq.llm.tools.translate_sigma_rule import TranslateSigmaRuleTool
from sigmaiq.llm.tools.find_sigma_rule import FindSigmaRuleTool
from sigmaiq.llm.tools.query_to_sigma_rule import QueryToSigmaRuleTool


class SigmaToolkit(BaseToolkit):
    """Sigma Toolkit."""

    sigmadb: VectorStore
    rule_creation_llm: BaseLanguageModel

    class Config:
        arbitrary_types_allowed = True

    def get_tools(self) -> List[BaseTool]:
        """Get the tools in the toolkit."""
        return [
            FindSigmaRuleTool(sigmadb=self.sigmadb, llm=self.rule_creation_llm),
            TranslateSigmaRuleTool(),
            CreateSigmaRuleVectorStoreTool(sigmadb=self.sigmadb, llm=self.rule_creation_llm),
            QueryToSigmaRuleTool(llm=self.rule_creation_llm),
        ]
