# stdlib
import os
from typing import Type, List

# sigmaiq
from sigmaiq.utils.sigma.rule_updater import SigmaRuleUpdater
from sigmaiq.globals import DEFAULT_DIRS

# langchain
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.document_loaders import DirectoryLoader, TextLoader
from langchain.text_splitter import CharacterTextSplitter

# langchain typing
from langchain.schema.embeddings import Embeddings
from langchain.schema.vectorstore import VectorStore
from langchain.document_loaders.base import BaseLoader, Document
from langchain.schema.document import BaseDocumentTransformer


class SigmaLLM(SigmaRuleUpdater):
    """Base class for Sigma rules with LLMs.
    Provides methods for ensuring the latest Sigma rule package is installed, creating embeddings from Sigma rules,
    and storing them in a vector store. Also provides basic search functionality based on the vector store embeddings.

    All agents, tools, and toolkits are in separate classes.

    To use custom embeddings, text splitters, loaders, etc, provide them as args override the methods in this class as
    needed by your custom passed classes.
    """

    def __init__(
        self,
        rule_dir: str = None,
        vector_store_dir: str = None,
        embedding_function: Type[Embeddings] = OpenAIEmbeddings,
        vector_store: Type[VectorStore] = FAISS,
        rule_loader: Type[BaseLoader] = DirectoryLoader,
        rule_splitter: Type[BaseDocumentTransformer] = CharacterTextSplitter,
    ):
        """Initializes the SigmaLLM object.
        If passing custom embeddings, vector stores, loaders, or splitters, pass the class itself rather than
        an instance of the class. For example, pass `OpenAIEmbeddings` instead of `OpenAIEmbeddings()`. Then, override
        the methods in this class to load the custom classes if needed.

        Requires environmental variable `OPENAI_API_KEY` to be set to your OpenAI API key if using any OpenAI models
        or embeddings.

        Args:
            rule_dir (str, optional): The directory to store the Sigma rules. Defaults to None.
            vector_store_dir (str, optional): The directory to store the vector store. Defaults to None.
            embedding_function (Type[Embeddings], optional): The Embeddings class to use for Sigma rule embeddings. Defaults to OpenAIEmbeddings.
            vector_store (Type[VectorStore], optional): The VectorStore class to use for Sigma rule embeddings. Defaults to FAISS.
            rule_loader (Type[BaseLoader], optional): The DocumentLoader class to use for loading Sigma rules. Defaults to DirectoryLoader.
            rule_splitter (Type[BaseDocumentTransformer], optional): The DocumentTransformer class to use for splitting Sigma rules. Defaults to CharacterTextSplitter.
        """
        # Download/update sigma rules from parent class
        super().__init__(rule_dir=rule_dir)

        # Setup rest of class
        self.vector_store_dir = self._setup_vector_store_dir(vector_store_dir)
        self.embedding_function = embedding_function()
        self.vector_store = vector_store
        self.sigmadb = None
        self.rule_loader = rule_loader
        self.rule_splitter = rule_splitter

    def load_sigma_vectordb(self):
        """Loads the Sigma rule vector store.
        Override `load_local()` below with how your vector store class loads local Vector DBs"""
        if not os.path.exists(self.vector_store_dir):
            raise FileNotFoundError(f"VectorStore not found at {self.vector_store_dir}.")
        try:
            self.sigmadb = self.vector_store.load_local(  # CHANGE ME IF NEEDED
                folder_path=self.vector_store_dir,
                embeddings=self.embedding_function,
            )
        except Exception as e:
            raise e

    def create_sigma_vectordb(self, save: bool = True):
        """Creates Sigma rule vector store by performing the following actions:
            1. Load each Sigma rule from the local SigmaHQ Sigma rules repository as Documents
            2. Split each Sigma rule Document
            3. Embed each Sigma rule Document and store in VectorStore
            4. Save the vectordb (if arg set) to disk

        Each of these steps has its own associated method; override them if you would like to change its behavior, for
        example, by using a different TextSplitter or VectorStore.

        Args:
            save (bool, optional): If True, will save the VectorStore to disk. Defaults to True.

        """
        if not self.installed_tag:
            self.update_sigma_rules()

        # Load Sigma docs
        sigma_docs = self.create_sigma_rule_docs()
        print(f"Loaded {len(sigma_docs)} Sigma rules")
        # Split Sigma docs
        sigma_docs = self.split_sigma_docs(sigma_docs)
        # Create VectorStore
        self.create_vectordb(sigma_docs)
        print(f"Created Sigma vectordb at {self.vector_store_dir}")
        # Save VectorStore
        if save:
            self.save_vectordb()

    def create_sigma_rule_docs(self) -> List[Document]:
        """Generator to loads Sigma rules from the local SigmaHQ Sigma rules repository."""
        sigma_rule_docs = []
        sigma_rule_docs += self.rule_loader(self.rule_dir, glob="**/*.yml", loader_cls=TextLoader).load()

        return sigma_rule_docs

    def split_sigma_docs(self, sigma_docs) -> List[Document]:
        """Splits Sigma rule Documents into chunks based on the DirectoryLoader provided on initialization.
        By default, we don't want to split up rules much, as we want the whole rule embedded. If you want to split
        rules into smaller chunks, override this method and return the chunks, or use your own text splitter in initialization.

        Args:
            sigma_docs (List[Document]): The list of Sigma rule Documents to split.

        Returns:
            List[Document]: The list of Sigma rule Documents, split into chunks.
        """
        # Override if needed
        self.rule_splitter = self.rule_splitter(chunk_size=99999)  # only chunk if rule is larger than 99999 characters
        return self.rule_splitter.split_documents(sigma_docs)

    def create_vectordb(self, sigma_docs: List[Document]):
        """Creates the VectorStore from the Sigma rule Documents.
        Override `from_documents()` below with how your vector store class adds documents to the Vector DB"""
        self.sigmadb = self.vector_store.from_documents(sigma_docs, self.embedding_function)  # CHANGE ME IF NEEDED

    def save_vectordb(self, vectordb_path: str = None):
        """Saves the VectorStore to disk. If no path is provided, will save to the path provided on initialization.
        Override `save_local()` below with how your vector store class saves local Vector DBs

        Args:
            vectordb_path (str, optional): The path to save the VectorStore. Defaults to None and will use the path provided on initialization.
        """

        self.sigmadb.save_local(self.vector_store_dir)

    @staticmethod
    def _setup_vector_store_dir(vector_store_dir: str = None) -> str:
        """Checks if the vector store directory exists. If not, creates it.

        Args:
            vector_store_dir (str, optional): The directory to store the vector store. Defaults to None.

        Returns:
            str: The vector store directory path.
        """
        if not vector_store_dir:
            vector_store_dir = DEFAULT_DIRS.VECTOR_STORE_DIR
        if not os.path.exists(vector_store_dir):
            os.makedirs(vector_store_dir)
        return vector_store_dir

    def simple_search(self, query: str, k: int = 3) -> List[Document]:
        """Searches the Sigma rule vector store for the query text using similarity search.

        Args:
            query (str): The query text to search for.
            k (int, optional): The number of results to return. Defaults to 3.

        Returns:
            List[Document]: The top 'k' matching Sigma Rules from the search.
        """
        if not self.sigmadb:
            self.load_sigma_vectordb()
        return self.sigmadb.similarity_search(query, k)
