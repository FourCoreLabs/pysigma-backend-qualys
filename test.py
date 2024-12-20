from sigma.rule import SigmaRule
from sigma.backends.qualys import QualysBackend
from sigma.pipelines.qualys import qualys_pipeline

backend = QualysBackend(processing_pipeline=qualys_pipeline())

with open("rule.yml", "r") as f:
    rule = SigmaRule.from_yaml(f.read())
    queries = backend.convert_rule(rule)
    print(f"Title: {rule.title}")
    print(f"Query: {queries[0]}")