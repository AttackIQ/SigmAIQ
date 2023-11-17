# stdlib
from typing import Type, Optional

# langchain
from langchain.callbacks.manager import CallbackManagerForToolRun
from langchain.prompts import ChatPromptTemplate
from langchain.tools import BaseTool
from langchain.pydantic_v1 import BaseModel, Field

# langchain typing
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.vectorstore import VectorStore


class CreateSigmaRuleInput(BaseModel):
    """Input for TranslateSigmaRule tool, which uses SigmAIQ backend factory to convert a Sigma Rule into
    a query for a specific backend."""

    query: str = Field(
        description="The users question, used to search through the Sigma VectorStore and create a Sigma Rule."
    )

    class Config(BaseTool.Config):
        pass


class CreateSigmaRuleVectorStoreTool(BaseTool):
    """Class for translating Sigma rules via SigmAIQ Backend Factory"""

    name: str = "create_sigma_rule_vectorstore"
    args_schema: Type[BaseModel] = CreateSigmaRuleInput
    description: str = """Use this tool to take the users input, find similar Sigma Rules from the vectorstore,
    then create a brand new Sigma Rule based on the users input and the similar Sigma Rules returned from the vectorstore
    to use as context. The output is a Sigma Rule in YAML format.
    """
    sigmadb: VectorStore
    llm: BaseLanguageModel
    k: int = 3
    verbose = True

    def _run(
        self,
        query: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """Run the tool"""

        template = """You are a cybersecurity detection engineering assistant bot specializing in Sigma Rule creation.
                You are assisting a user in creating a new Sigma Rule based on the users question.  
                The users question is first used to find similar Sigma Rules from the a vectorstore containing official 
                Sigma Rules. The official Sigma Rules should be used as context as needed in conjunction with the detection specified
                in the users question to create a new Sigma Rule. Set the 'author' to 'SigmAIQ (AttackIQ)', 
                the date to today's date, and the reference to 'https://github.com/AttackIQ/SigmAIQ'.  
                The created Sigma Rule should be in YAML format and use the official Sigma schema.  The detection field
                can contain multiple 'selection' identifiers and multiple 'filter' identifiers as needed, 
                which can be used in the condition field to select criteria and filter out criteria respectively.

                Sigma Rule Schema:
                
                title
                id [optional]
                related [optional]
                   - id {{rule-id}}
                     type {{type-identifier}}
                status [optional]
                description [optional]
                references [optional]
                author [optional]
                date [optional]
                modified [optional]
                tags [optional]
                logsource
                   category [optional]
                   product [optional]
                   service [optional]
                   definition [optional]
                   ...
                detection
                   {{search-identifier}} [optional]
                      {{string-list}} [optional]
                      {{map-list}} [optional]
                      {{field: valu}}> [optional]
                   ... # Multiple search identifiers can be specified as needed and used in the condition
                   condition
                fields [optional]
                falsepositives [optional]
                level [optional]:
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
        query: str,
        k: int,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """Async run the tool"""
        raise NotImplementedError
