# pySigma Qualys Backend
This is the Qualys backend for pySigma. It provides the package `sigma.backends.qualys` with the QualysBackend class for converting Sigma rules to Qualys query language.


## Supported Processing Pipelines
The backend includes a Qualys processing pipeline under `sigma.pipelines.qualys`:
- `qualys_pipeline`: A comprehensive processing pipeline for converting Sigma rules to Qualys compatible queries, with extensive field mapping support.

## Supported Rules and Categories
The Qualys pipeline supports the following event categories and products:

| Category | Product | Supported Events |
|----------|---------|-----------------|
| `process_creation` | `windows` | Process creation, execution tracking |
| `file_access` | `windows` | File system access and modification events |
| `network_connection` | `windows` | Network connection events |
| `registry_set` | `windows` | Registry modification events |
| `image_load` | `windows` | Module and library loading events |
| `file_event` | `windows` | File-related events (creation, deletion, modification) |

## Limitations and Caveats
* **Event Type Specificity**: The backend focuses on Windows-based event types and may have limited support for other platforms.

## Installation

```bash
pip install pysigma-backend-qualys
```

## Usage Example

```python
from sigma.rule import SigmaRule
from sigma.backends.qualys import QualysBackend
from sigma.pipelines.qualys import qualys_pipeline

# Create a Qualys backend with the processing pipeline
backend = QualysBackend(processing_pipeline=qualys_pipeline())

# Convert a Sigma rule to a Qualys query
rule = SigmaRule.from_yaml("""
title: Detect Suspicious Process
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\\Windows\\System32\\cmd.exe'
    condition: selection
""")

# Generate Qualys query
qualys_query = backend.convert_rule(rule)
print(qualys_query)
```

## References

[Qualys Events Search Token](https://docs.qualys.com/en/edr/latest/search_tips/search_ui_events.htm) 

## Contributing

Contributions are welcome! Please submit issues and pull requests to the project repository.

