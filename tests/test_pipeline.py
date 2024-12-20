import unittest
import re
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.pipelines.qualys import qualys_pipeline

class TestQualysPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = qualys_pipeline()

    def _test_field_mapping(self, sigma_field, qualys_field, rule_yaml):
        """
        Generic method to test field mappings
        
        Args:
            sigma_field (str): Original Sigma field name
            qualys_field (str): Expected Qualys field name
            rule_yaml (str): YAML representation of the Sigma rule
        """
        rule = SigmaRule.from_yaml(rule_yaml)
        processed = self.pipeline.apply(rule)
        self.assertIn(qualys_field, str(processed), 
                      f"Field mapping from {sigma_field} to {qualys_field} failed")

    def test_field_mappings(self):
        """Test field mappings for various event types"""
        test_cases = [
            {
                "sigma_field": "Image", 
                "qualys_field": "process.image.fullPath", 
                "rule_yaml": """
                    title: Test Image Mapping
                    logsource:
                        category: process_creation
                        product: windows
                    detection:
                        selection:
                            Image: test_value
                        condition: selection
                """
            },
            {
                "sigma_field": "CommandLine", 
                "qualys_field": "process.arguments", 
                "rule_yaml": """
                    title: Test CommandLine Mapping
                    logsource:
                        category: process_creation
                        product: windows
                    detection:
                        selection:
                            CommandLine: test_value
                        condition: selection
                """
            },
            {
                "sigma_field": "TargetFilename", 
                "qualys_field": "file.fullPath", 
                "rule_yaml": """
                    title: Test TargetFilename Mapping
                    logsource:
                        category: file_access
                        product: windows
                    detection:
                        selection:
                            TargetFilename: test_value
                        condition: selection
                """
            },
            {
                "sigma_field": "SourceIp", 
                "qualys_field": "network.local.address.ip", 
                "rule_yaml": """
                    title: Test SourceIp Mapping
                    logsource:
                        category: network_connection
                        product: windows
                    detection:
                        selection:
                            SourceIp: 192.168.1.1
                        condition: selection
                """
            }
        ]
        # test for each case
        for case in test_cases:
            with self.subTest(field=case['sigma_field']):
                self._test_field_mapping(
                    case['sigma_field'], 
                    case['qualys_field'], 
                    case['rule_yaml']
                )

    def test_process_creation_pipeline(self):
        """Test process creation event pipeline"""
        rule = SigmaRule.from_yaml("""
            title: Test Process Creation
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|contains: 'test.exe'
                    Image: 'C:\\Windows\\test.exe'
                condition: selection
        """)
        processed = self.pipeline.apply(rule)
        result = str(processed)
        self.assertIn("process.arguments", result)
        self.assertIn("process.image.fullPath", result)

    def test_file_access_pipeline(self):
        """Test file access event pipeline"""
        rule = SigmaRule.from_yaml("""
            title: Test File Access
            logsource:
                category: file_access
                product: windows
            detection:
                selection:
                    TargetFilename|contains: 'test.txt'
                condition: selection
        """)
        processed = self.pipeline.apply(rule)
        result = str(processed)
        self.assertIn("file.fullPath", result)

    def test_registry_pipeline(self):
        """Test registry event pipeline"""
        rule = SigmaRule.from_yaml("""
            title: Test Registry
            logsource:
                category: registry_set
                product: windows
            detection:
                selection:
                    TargetObject: 'HKLM:\\Software\\Test'
                    Details: 'test_value'
                condition: selection
        """)
        processed = self.pipeline.apply(rule)
        result = str(processed)
        self.assertIn("registry.key", result)
        self.assertIn("registry.data", result)

    def test_network_pipeline(self):
        """Test network event pipeline"""
        rule = SigmaRule.from_yaml("""
            title: Test Network
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    DestinationIp: '192.168.1.1'
                    DestinationPort: 445
                condition: selection
        """)
        processed = self.pipeline.apply(rule)
        result = str(processed)
        self.assertIn("network.remote.address.ip", result)
        self.assertIn("network.remote.address.port", result)

    def test_hash_pipeline(self):
        """Test hash value pipeline"""
        rule = SigmaRule.from_yaml("""
            title: Test Hashes
            logsource:
                category: file_event
                product: windows
            detection:
                selection:
                    MD5: 'd41d8cd98f00b204e9800998ecf8427e'
                    SHA256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
                condition: selection
        """)
        processed = self.pipeline.apply(rule)
        result = str(processed)
        self.assertIn("file.hash.md5", result)
        self.assertIn("file.hash.sha256", result)

if __name__ == '__main__':
    unittest.main(verbosity=2)