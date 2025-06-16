import unittest
from unittest.mock import patch
from src.device_scanner import scan_devices

class TestDeviceScanner(unittest.TestCase):
    @patch("nmap.PortScanner")
    def test_scan_devices(self, mock_scanner):
        """Test device scanning."""
        mock_scanner.return_value.all_hosts.return_value = ["192.168.1.1"]
        mock_scanner.return_value.__getitem__.return_value = {
            "addresses": {"mac": "00:11:22:33:44:55"},
            "status": {"state": "up"},
            "tcp": {}
        }
        devices = scan_devices("192.168.1.0/24")
        self.assertIsInstance(devices, list)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "192.168.1.1")

if __name__ == "__main__":
    unittest.main()