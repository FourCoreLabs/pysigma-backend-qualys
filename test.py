from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.qualys.qualys import QualysBackend
from sigma.pipelines.qualys.qualys import qualys_windows_pipeline

def main():
    backend = QualysBackend(processing_pipeline=qualys_windows_pipeline())
    rules = SigmaCollection.load_ruleset(list(Path(".").glob("*.yml")))
    
    for rule in rules.rules:
        print(f"Title: {rule.title}")
        print(f"Query: {backend.convert_rule(rule)[0]}\n")

if __name__ == "__main__":
    main()