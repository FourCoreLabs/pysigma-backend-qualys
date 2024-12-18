from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation

def qualys_windows_pipeline():
    """Pipeline for converting Sigma rules into Qualys queries for Windows events."""
    return ProcessingPipeline(
        name="Qualys Windows pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="qualys_field_mapping",
                transformation=FieldMappingTransformation({
                    "Image": "process.image.fullPath",
                    "OriginalFileName": "process.originalfilename",
                    "CommandLine": "process.arguments",
                    "ParentImage": "parent.image.fullPath",
                    "ParentCommandLine": "parent.arguments",
                    "User": "process.username",
                    "ObjectName": "process.name"
                })
            )
        ]
    )