from typing import Optional
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation

QUALYS_FIELD_MAPPINGS = {
    # Process Events
    "ProcessId": "process.pid",
    "Image": "process.image.fullPath",
    "FileVersion": "process.fileversion",
    "Description": "process.description",
    "Product": "process.productname",
    "Company": "process.company",
    "OriginalFileName": "process.originalfilename",
    "CommandLine": "process.arguments",
    "CurrentDirectory": "process.currentdirectory",
    "User": "process.username",
    "IntegrityLevel": "process.integritylevel",
    "ParentProcessId": "parent.pid",
    "ParentImage": "parent.imagepath",
    "ParentCommandLine": "parent.commandline",
    "ParentUser": "parent.username",
    "ParentIntegrityLevel": "parent.integritylevel",
    
    # File Events
    "TargetFilename": "file.fullPath",
    "CreationUtcTime": "file.created",
    "PreviousFileName": "file.previousname",
    "FileSize": "file.size",
    "FileType": "file.type",
    "FileCreationTime": "file.created",
    "FileModificationTime": "file.modified",
    "FileAccessTime": "file.accessed",
    
    # Network Events
    "SourceIp": "network.local.address.ip",
    "SourceHostname": "network.local.hostname",
    "SourcePort": "network.local.address.port",
    "DestinationIp": "network.remote.address.ip",
    "DestinationHostname": "network.remote.address.fqdn",
    "DestinationPort": "network.remote.address.port",
    "Protocol": "network.protocol",
    "NetworkDirection": "network.direction",
    "NetworkConnectionStatus": "network.state",
    
    # Registry Events
    "TargetObject": "registry.key",
    "Details": "registry.data",
    "NewName": "registry.newname",
    "EventType": "registry.type",
    "PreviousTargetObject": "registry.oldkey",
    "RegistryValueData": "registry.value.data",
    "RegistryValueName": "registry.value.name",
    "RegistryKeyPath": "registry.path",
    
    # Hash Fields
    "Hashes": "file.hash",
    "MD5": "file.hash.md5",
    "SHA1": "file.hash.sha1",
    "SHA256": "file.hash.sha256",
    "Imphash": "file.hash.imphash",
    
    # Event Fields
    "EventID": "event.id",
    "EventType": "event.type",
    "EventTime": "event.dateTime",
    "EventStatus": "event.status",
    "EventPid": "event.pid",
    "EventResult": "event.result",
    "EventCategory": "event.category",
    
    # AMSI Fields
    "AMSIProvider": "amsi.provider",
    "AMSIAppName": "amsi.application",
    "AMSIContent": "amsi.content",
    
    # Detection Fields
    "DetectionSource": "detection.source",
    "DetectionType": "detection.type",
    "ThreatName": "threat.name",
    "ThreatType": "threat.type",
    "ThreatCategory": "threat.category",
    "ThreatSeverity": "threat.severity",
    
    # Authentication Fields
    "AuthenticationProtocol": "auth.protocol",
    "LogonType": "logon.type",
    "LogonId": "logon.id",
    "SourceUserName": "source.user.name",
    "SourceDomainName": "source.user.domain",
    "TargetUserName": "target.user.name",
    "TargetDomainName": "target.user.domain",
    
    # Additional Context Fields
    "MachineName": "host.name",
    "MachineId": "host.id",
    "MachineGroup": "host.group",
    "MachineRole": "host.role",
    "IpAddress": "host.ip",
    "OSVersion": "host.os.version",
    "OSPlatform": "host.os.platform"
}

def qualys_pipeline(table_name: Optional[str] = None) -> ProcessingPipeline:
    """
    Creates a processing pipeline for converting Sigma rules to Qualys queries
    
    Args:
        table_name: Optional override for the target table name
    
    Returns:
        ProcessingPipeline: Pipeline configured for Qualys
    """
    return ProcessingPipeline(
        name="qualys_pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="qualys_field_mappings",
                transformation=FieldMappingTransformation(QUALYS_FIELD_MAPPINGS)
            )
        ],
        allowed_backends=frozenset(["qualys"])
    )