import unittest
from app import CiscoLegacyTransport, category_for, parse_descriptions, parse_interface_status, parse_link_events, parse_mac_address_table
import socket

STATUS_OUTPUT = '''\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   Office-PC          connected    20         a-full  a-100 10/100/1000BaseTX
Gi1/0/2                      notconnect   20           auto   auto 10/100/1000BaseTX
Gi1/0/3                      disabled     1            auto   auto 10/100/1000BaseTX
Gi1/0/4   Camera             err-disabled 30           auto   auto 10/100/1000BaseTX
'''
DESCRIPTION_OUTPUT = '''\
Interface                      Status         Protocol Description
Gi1/0/1                        up             up       Room 104 PC
Gi1/0/2                        down           down     Spare desk jack
'''
MAC_TABLE_OUTPUT = '''\
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  20    0011.2233.4455    DYNAMIC     Gi1/0/1
  20    00aa.bbcc.ddee    DYNAMIC     Gi1/0/1
  30    00ff.eedd.ccbb    STATIC      Gi1/0/4
  99    0000.0000.0001    STATIC      CPU
Total Mac Addresses for this criterion: 4
'''
LOG_OUTPUT = '''\
*Nov 25 10:30:11.741: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/47, changed state to down
*Nov 25 10:30:13.020: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/47, changed state to down
*Nov 25 10:31:02.401: %LINK-3-UPDOWN: Interface Gi1/0/47, changed state to up
*Nov 25 10:31:04.100: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi1/0/47, changed state to up
*Nov 25 10:34:00.000: %LINK-3-UPDOWN: Interface TenGigabitEthernet1/1/1, changed state to down
'''

class ParserTests(unittest.TestCase):
    def test_interface_status_mapping(self):
        ports = parse_interface_status(STATUS_OUTPUT)
        self.assertEqual([p.category for p in ports], ["active", "disconnected", "disabled", "error"])
        self.assertEqual(ports[0].name, "Office-PC")
        self.assertEqual(ports[3].status, "err-disabled")

    def test_descriptions(self):
        descriptions = parse_descriptions(DESCRIPTION_OUTPUT)
        self.assertEqual(descriptions["Gi1/0/1"], "Room 104 PC")

    def test_mac_address_table_maps_all_interface_macs(self):
        macs = parse_mac_address_table(MAC_TABLE_OUTPUT)
        self.assertEqual([entry.mac for entry in macs["Gi1/0/1"]], ["0011.2233.4455", "00aa.bbcc.ddee"])
        self.assertEqual(macs["Gi1/0/4"][0].entry_type, "static")
        self.assertNotIn("CPU", macs)

    def test_link_events_map_long_and_short_interface_names(self):
        events = parse_link_events(LOG_OUTPUT)
        self.assertEqual(len(events["Gi1/0/47"]), 4)
        self.assertEqual(events["Gi1/0/47"][0].state, "down")
        self.assertEqual(events["Gi1/0/47"][1].source, "LINEPROTO")
        self.assertEqual(events["Te1/1/1"][0].state, "down")

    def test_unknown_status(self):
        self.assertEqual(category_for("sfpInact"), "unknown")

    def test_legacy_cisco_kex_is_available_but_group1_is_not(self):
        left, right = socket.socketpair()
        try:
            transport = CiscoLegacyTransport(left)
            self.assertIn("diffie-hellman-group14-sha1", transport.get_security_options().kex)
            self.assertNotIn("diffie-hellman-group1-sha1", transport.get_security_options().kex)
            transport.close()
        finally:
            right.close()

if __name__ == "__main__":
    unittest.main()
