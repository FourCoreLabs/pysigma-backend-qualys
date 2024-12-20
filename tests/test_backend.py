import unittest
from sigma.rule import SigmaRule
from sigma.backends.qualys import QualysBackend
from sigma.pipelines.qualys import qualys_pipeline

class TestQualysBackend(unittest.TestCase):
    def setUp(self):
        self.backend = QualysBackend(processing_pipeline=qualys_pipeline())

    def test_get_ciminstance_av_detection(self):
        """Test Get-CimInstance Antivirus Detection Rule"""
        rule = SigmaRule.from_yaml("""
            title: Detection of Get-CimInstance for Antivirus Product Discovery
            logsource:
                product: windows
                category: ps_script
            detection:
                selection:
                    EventID: 4104
                    ScriptBlockText|contains|all:
                        - 'Get-CimInstance'
                        - 'root/SecurityCenter2'
                        - 'AntivirusProduct'
                condition: selection
        """)
        queries = self.backend.convert_rule(rule)
        print(f"\nAntivirus Detection Query: {queries[0]}")
        self.assertIn("Get-CimInstance", queries[0])
        self.assertIn("root/SecurityCenter2", queries[0])

    def test_browser_cred_access(self):
        """Test Browser Credential Access Detection Rule"""
        rule = SigmaRule.from_yaml("""
            title: Access Browser Credential Files
            logsource:
                category: file_access
                product: windows
            detection:
                selection_all:
                    FileName|contains:
                        - '\AppData\Local\Microsoft\Vault\'
                        - '\ProgramData\Microsoft\Vault\'
                condition: selection_all
        """)
        queries = self.backend.convert_rule(rule)
        print(f"\nBrowser Cred Access Query: {queries[0]}")
        self.assertIn("FileName", queries[0])
        self.assertIn("*\\ProgramData\\Microsoft\\Vault*", queries[0])

    def test_defender_disable(self):
        """Test Windows Defender Disable Detection Rule"""
        rule = SigmaRule.from_yaml("""
            title: Detection of Windows Defender Disabling
            logsource:
                category: registry_set
                product: windows
            detection:
                selection:
                    TargetObject|contains:
                        - '\\DisableAntiSpyware'
                        - '\\DisableAntiVirus'
                    Details: 'DWORD (0x00000000)'
                condition: selection
        """)
        queries = self.backend.convert_rule(rule)
        print(f"\nDefender Disable Query: {queries[0]}")
        self.assertIn("registry.key", queries[0])
        self.assertIn("DisableAntiSpyware", queries[0])

    def test_scheduled_task_creation(self):
        """Test Scheduled Task Creation Detection Rule"""
        rule = SigmaRule.from_yaml("""
            title: Suspicious Scheduled Task Creation
            logsource:
                product: windows
                service: security
            detection:
                selection:
                    EventID: 4698
                    TaskContent|contains:
                        - 'cmd.exe'
                        - 'powershell'
                condition: selection
        """)
        queries = self.backend.convert_rule(rule)
        print(f"\nScheduled Task Query: {queries[0]}")
        self.assertIn("cmd.exe", queries[0])
        self.assertIn("powershell", queries[0])

    def test_dsrole_load(self):
        """Test Dsrole.dll Load Detection Rule"""
        rule = SigmaRule.from_yaml("""
            title: Dsrole.dll Load from Non-Standard Locations
            logsource:
                category: image_load
                product: windows
            detection:
                selection:
                    ImageLoaded|endswith: '\\dsrole.dll'
                filter:
                    ImageLoaded:
                        - 'C:\\Windows\\System32\\'
                condition: selection and not filter
        """)
        queries = self.backend.convert_rule(rule)
        print(f"\nDsrole Load Query: {queries[0]}")
        self.assertIn("dsrole.dll", queries[0])

    def test_certutil_network(self):
        """Test Certutil Network Connection Detection Rule"""
        rule = SigmaRule.from_yaml("""
            title: Connection Initiated using Certutil
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    Image|endswith: '\\certutil.exe'
                    Initiated: 'true'
                    DestinationPort:
                        - 80
                        - 443
                condition: selection
        """)
        queries = self.backend.convert_rule(rule)
        print(f"\nCertutil Network Query: {queries[0]}")
        self.assertIn("certutil.exe", queries[0])

if __name__ == '__main__':
    unittest.main(verbosity=2)