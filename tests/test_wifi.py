import unittest
from unittest.mock import patch
from src.wifi_scanner import validate_mac, scan_wifi_networks

class TestWifiScanner(unittest.TestCase):
    def test_validate_mac(self):
        """Test MAC address validation."""
        self.assertTrue(validate_mac("00:11:22:33:44:55"))
        self.assertFalse(validate_mac("00:11:22:33:44"))
        self.assertFalse(validate_mac("GG:HH:II:JJ:KK:LL"))
    
    @patch("scapy.all.sniff")
    def test_scan_wifi_networks(self, mock_sniff):
        """Test Wi-Fi network scanning."""
        mock_sniff.return_value = []
        networks = scan_wifi_networks("wlan0", timeout=1)
        self.assertIsInstance(networks, set)
        mock_sniff.assert_called_once()

if __name__ == "__main__":
    unittest.main()