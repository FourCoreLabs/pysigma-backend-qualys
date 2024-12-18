import pytest
from sigma.rule import SigmaRule
from sigma.backends.qualys.qualys import QualysBackend
from sigma.pipelines.qualys.qualys import qualys_windows_pipeline

def test_qualys_wmic_group_enum():
    rule = SigmaRule.from_yaml("""
title: Detect Group Enumeration using WMIC (via Process Creation)
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection_proc:
        - Image|endswith: '\\wmic.exe'
        - OriginalFileName: 'wmic.exe'
        - ObjectName|contains: 'wmic.exe'
    selection_params:
        CommandLine|contains|all: 
            - 'group'
            - 'get'
            - 'name'
    condition: selection_proc and selection_params
    """)

    backend = QualysBackend(processing_pipeline=qualys_windows_pipeline())
    result = backend.convert_rule(rule)

    expected_query = '((process.image.fullPath:"*\\wmic.exe" OR process.originalfilename:"wmic.exe" OR process.name:"*wmic.exe*") AND (process.arguments:"*group*" AND process.arguments:"*get*" AND process.arguments:"*name*"))'
    assert result[0] == expected_query

if __name__ == "__main__":
    pytest.main([__file__])