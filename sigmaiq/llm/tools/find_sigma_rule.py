import json
from typing import Union, Type, Optional
from langchain.callbacks.manager import CallbackManagerForToolRun
from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool
from pydantic import BaseModel, Field, Extra



class FindSigmaRuleInput(BaseModel):
    """Input for QueryToSigmaRule tool, which converts a backend query to a Sigma Rule, and
    uses SigmAIQ backend factory for validation.
    """

    query: Union[str, dict] = Field(
        default=None,
        description="""A query string for a backend, which should be converted to a Sigma Rule YAML string."""
    )


class FindSigmaRuleTool(BaseTool):
    """Class for searching Sigma rules in the vector database"""

    name: str = "find_sigma_rule"
    args_schema: Type[BaseModel] = FindSigmaRuleInput
    description: str = """
        Use this tool to search for a Sigma Rule in the vector database. The input should be relevent information, such as
        log artifacts, event IDs, operating systems, categories, indicators of compromise, MITRE ATT&CK information, or other relevant information to use
        to search the vector store. If multiple rules are returned from the vector store, select the most similar Sigma Rule and return it in YAML format.
        """
    # return_direct = True  # We don't need an agent LLM to think about the output, it is what it is.
    llm: BaseLanguageModel
    sigmadb: VectorStore
    k: int = 3
    verbose = False

    class Config:
        """Configuration for this pydantic object."""

        extra = Extra.forbid

    def _run(
        self,
        query: str = None,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        template = """You are a cybersecurity detection engineering assistant bot specializing in Sigma Rules.
                    You are assisting a user searching for Sigma Rules stored in a vectorstore.
                    Based on the users question, extract the relevent information, such as
                    log artifacts, event IDs, operating systems, categories, indicators of compromise, 
                    MITRE ATT&CK information, or other relevant information to use
                    to search the vector store. If multiple rules are returned from the 
                    vector store, select the most similar Sigma Rule and return it in YAML format. Output the entire rule.
                    -------
                    Vectorstore Search Results:
    
                    {context}
                    ------
                    User's Question: 
                    {question}
                """

        prompt = ChatPromptTemplate.from_template(template)
        retriever = self.sigmadb.as_retriever(search_kwargs={"k": self.k})
        chain = {"context": retriever, "question": RunnablePassthrough()} | prompt | self.llm | StrOutputParser()
        return chain.invoke(query)

    async def _arun(
        self,
        query: Union[str, dict] = None,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """Async run the tool"""
        raise NotImplementedError
