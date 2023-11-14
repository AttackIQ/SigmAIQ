import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SIGMA_RULE_DIR = os.path.join(ROOT_DIR, "llm/data/sigma")

print(SIGMA_RULE_DIR)