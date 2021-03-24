#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.

"""rtpcap_unittest.py: simple unittest.


"""

import importlib
import unittest

rtpcap = importlib.import_module('rtpcap')


getPacketLossAndOutOfOrderTestCases = [
    {
        'name': 'basic',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 3, 4],
        'ploss': 0,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'wraparound 65536',
        'rtp_seq_prev': 65534,
        'rtp_seq_list': [65535, 0, 1],
        'ploss': 0,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 1,
    },
    {
        'name': 'empty rtp_seq_prev',
        'rtp_seq_prev': None,
        'rtp_seq_list': [2, 3, 4],
        'ploss': 0,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'empty rtp_seq_list',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [],
        'ploss': 0,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 1,
    },
    {
        'name': 'ploss 1',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 4],
        'ploss': 1,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'ploss 2',
        'rtp_seq_prev': 0,
        'rtp_seq_list': [2, 3],
        'ploss': 1,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 3,
    },
    {
        'name': 'porder 1',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 4, 3],
        'ploss': 0,
        'porder': 1,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'porder 2',
        'rtp_seq_prev': 2,
        'rtp_seq_list': [1, 3, 4],
        'ploss': 0,
        'porder': 1,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'pdups 1',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 3, 3, 4],
        'ploss': 0,
        'porder': 0,
        'pdups': 1,
        'rtp_seq_max': 4,
    },
    {
        'name': 'pdups 2',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [1, 2, 3, 4],
        'ploss': 0,
        'porder': 0,
        'pdups': 1,
        'rtp_seq_max': 4,
    },
    {
        'name': 'porder and ploss',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 4, 3, 6],
        'ploss': 1,
        'porder': 1,
        'pdups': 0,
        'rtp_seq_max': 6,
    },
    {
        'name': 'porder and pdups',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 4, 3, 3],
        'ploss': 0,
        'porder': 1,
        'pdups': 1,
        'rtp_seq_max': 4,
    },
    {
        'name': 'ploss and pdups',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 2, 4, 5],
        'ploss': 1,
        'porder': 0,
        'pdups': 1,
        'rtp_seq_max': 5,
    },
    {
        'name': 'porder, ploss, pdups',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 2, 5, 4],
        'ploss': 1,
        'porder': 1,
        'pdups': 1,
        'rtp_seq_max': 5,
    },
]


analyzeVideoFrameTestCases = [
    {
        'name': 'basic',
        'parsed_rtp_list': [
            {
                'frame_number': 164,
                'frame_time_relative': 8.258306,
                'frame_time_epoch': 1596055127.588039,
                'ip_src': '192.0.2.1',
                'ip_len': 115,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9017,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 1,
            },
            {
                'frame_number': 166,
                'frame_time_relative': 8.263017,
                'frame_time_epoch': 1596055127.59275,
                'ip_src': '192.0.2.1',
                'ip_len': 1137,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9018,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 2,
            },
            {
                'frame_number': 168,
                'frame_time_relative': 8.271022,
                'frame_time_epoch': 1596055127.600755,
                'ip_src': '192.0.2.1',
                'ip_len': 1137,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9019,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 3,
            },
            {
                'frame_number': 169,
                'frame_time_relative': 8.279998,
                'frame_time_epoch': 1596055127.609731,
                'ip_src': '192.0.2.1',
                'ip_len': 1137,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9020,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 4,
            },
            {
                'frame_number': 174,
                'frame_time_relative': 8.292757,
                'frame_time_epoch': 1596055127.62249,
                'ip_src': '192.0.2.1',
                'ip_len': 1137,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9021,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 5,
            },
        ],
        'out_data': [
            # 'frame_time_relative', 'frame_time_epoch',
            # 'frame_time_intra_latency', 'frame_time_inter_latency',
            # 'rtp_timestamp', 'rtp_timestamp_inter_latency',
            # 'packets', 'ploss', 'porder', 'pdups', 'bytes',
            # 'frame_video_type', 'rtp_seq_list'
            [8.258306, 1596055127.588039,
             0.03445100784301758, 0.03445100784301758,
             541511905, 0,
             5, 0, 0, 0, 4663, 'I',
             rtpcap.SEP.join([str(i) for i in [9017, 9018, 9019, 9020, 9021]]),
             ],
        ],
    },
]

parseUdpConnectionsTestCases = [
    {
        'name': 'basic',
        'tshark': b"""
================================================================================
UDP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
2601:641:400:2c50:d32b:9a55:67fc:5532:54986 <-> 2a03:2880:f231:cd:face:b00c:0:6443:40003    9915 9,018kB     14692 13MB        24607 22MB         20.519120000        93.6031
192.168.0.1:1901           <-> 239.255.255.250:1900             0 0bytes         43 15kB           43 15kB         12.011178000       113.3792
192.168.0.1:1900           <-> 239.255.255.250:1900             0 0bytes         18 6,311bytes      18 6,311bytes     2.181443000       115.8235
192.168.0.4:5353           <-> 224.0.0.251:5353                 0 0bytes         15 7,284bytes      15 7,284bytes     0.489531000       127.8043
fe80::eeac:ba3c:e956:d895:5353 <-> ff02::fb:5353                    0 0bytes         11 6,516bytes      11 6,516bytes     0.489786000       127.8044
192.168.0.8:53514          <-> 239.255.255.250:1900             0 0bytes          4 868bytes        4 868bytes      5.560528000         2.9654
192.168.0.8:53514          <-> 192.168.0.4:1900                 4 1,344bytes       0 0bytes          4 1,344bytes     5.562314000         2.9648
192.168.0.8:63985          <-> 239.255.255.250:1900             0 0bytes          4 868bytes        4 868bytes    125.474775000         3.0684
192.168.0.8:63985          <-> 192.168.0.4:1900                 4 1,344bytes       0 0bytes          4 1,344bytes   125.476161000         3.0685
192.168.0.4:48588          <-> 157.240.22.60:40003              1 106bytes        1 150bytes        2 256bytes     20.469660000         0.0738
2601:641:400:2c50:e119:160b:b2e8:2cd4:57896 <-> 2001:558:feed::2:53              1 122bytes        1 94bytes         2 216bytes    105.848834000         0.0443
2601:641:400:2c50:e119:160b:b2e8:2cd4:15677 <-> 2001:558:feed::2:53              1 137bytes        1 109bytes        2 246bytes    105.867758000         0.0529
192.168.0.8:138            <-> 192.168.0.255:138                0 0bytes          1 240bytes        1 240bytes    126.800768000         0.0000
================================================================================
""",
        'udp_connections': [
            {
                'proto': 'ipv6',
                'laddr': '2601:641:400:2c50:d32b:9a55:67fc:5532',
                'lport': '54986',
                'raddr': '2a03:2880:f231:cd:face:b00c:0:6443',
                'rport': '40003',
                'rpkts': '9915',
                'rbytes': '9,018kB',
                'lpkts': '14692',
                'lbytes': '13MB',
                'tpkts': '24607',
                'tbytes': '22MB',
                'start': '20.519120000',
                'duration': '93.6031',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.1',
                'lport': '1901',
                'raddr': '239.255.255.250',
                'rport': '1900',
                'rpkts': '0',
                'rbytes': '0bytes',
                'lpkts': '43',
                'lbytes': '15kB',
                'tpkts': '43',
                'tbytes': '15kB',
                'start': '12.011178000',
                'duration': '113.3792',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.1',
                'lport': '1900',
                'raddr': '239.255.255.250',
                'rport': '1900',
                'rpkts': '0',
                'rbytes': '0bytes',
                'lpkts': '18',
                'lbytes': '6,311bytes',
                'tpkts': '18',
                'tbytes': '6,311bytes',
                'start': '2.181443000',
                'duration': '115.8235',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.4',
                'lport': '5353',
                'raddr': '224.0.0.251',
                'rport': '5353',
                'rpkts': '0',
                'rbytes': '0bytes',
                'lpkts': '15',
                'lbytes': '7,284bytes',
                'tpkts': '15',
                'tbytes': '7,284bytes',
                'start': '0.489531000',
                'duration': '127.8043',
            },
            {
                'proto': 'ipv6',
                'laddr': 'fe80::eeac:ba3c:e956:d895',
                'lport': '5353',
                'raddr': 'ff02::fb',
                'rport': '5353',
                'rpkts': '0',
                'rbytes': '0bytes',
                'lpkts': '11',
                'lbytes': '6,516bytes',
                'tpkts': '11',
                'tbytes': '6,516bytes',
                'start': '0.489786000',
                'duration': '127.8044',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.8',
                'lport': '53514',
                'raddr': '239.255.255.250',
                'rport': '1900',
                'rpkts': '0',
                'rbytes': '0bytes',
                'lpkts': '4',
                'lbytes': '868bytes',
                'tpkts': '4',
                'tbytes': '868bytes',
                'start': '5.560528000',
                'duration': '2.9654',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.8',
                'lport': '53514',
                'raddr': '192.168.0.4',
                'rport': '1900',
                'rpkts': '4',
                'rbytes': '1,344bytes',
                'lpkts': '0',
                'lbytes': '0bytes',
                'tpkts': '4',
                'tbytes': '1,344bytes',
                'start': '5.562314000',
                'duration': '2.9648',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.8',
                'lport': '63985',
                'raddr': '239.255.255.250',
                'rport': '1900',
                'rpkts': '0',
                'rbytes': '0bytes',
                'lpkts': '4',
                'lbytes': '868bytes',
                'tpkts': '4',
                'tbytes': '868bytes',
                'start': '125.474775000',
                'duration': '3.0684',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.8',
                'lport': '63985',
                'raddr': '192.168.0.4',
                'rport': '1900',
                'rpkts': '4',
                'rbytes': '1,344bytes',
                'lpkts': '0',
                'lbytes': '0bytes',
                'tpkts': '4',
                'tbytes': '1,344bytes',
                'start': '125.476161000',
                'duration': '3.0685',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.4',
                'lport': '48588',
                'raddr': '157.240.22.60',
                'rport': '40003',
                'rpkts': '1',
                'rbytes': '106bytes',
                'lpkts': '1',
                'lbytes': '150bytes',
                'tpkts': '2',
                'tbytes': '256bytes',
                'start': '20.469660000',
                'duration': '0.0738',
            },
            {
                'proto': 'ipv6',
                'laddr': '2601:641:400:2c50:e119:160b:b2e8:2cd4',
                'lport': '57896',
                'raddr': '2001:558:feed::2',
                'rport': '53',
                'rpkts': '1',
                'rbytes': '122bytes',
                'lpkts': '1',
                'lbytes': '94bytes',
                'tpkts': '2',
                'tbytes': '216bytes',
                'start': '105.848834000',
                'duration': '0.0443',
            },
            {
                'proto': 'ipv6',
                'laddr': '2601:641:400:2c50:e119:160b:b2e8:2cd4',
                'lport': '15677',
                'raddr': '2001:558:feed::2',
                'rport': '53',
                'rpkts': '1',
                'rbytes': '137bytes',
                'lpkts': '1',
                'lbytes': '109bytes',
                'tpkts': '2',
                'tbytes': '246bytes',
                'start': '105.867758000',
                'duration': '0.0529',
            },
            {
                'proto': 'ip',
                'laddr': '192.168.0.8',
                'lport': '138',
                'raddr': '192.168.0.255',
                'rport': '138',
                'rpkts': '0',
                'rbytes': '0bytes',
                'lpkts': '1',
                'lbytes': '240bytes',
                'tpkts': '1',
                'tbytes': '240bytes',
                'start': '126.800768000',
                'duration': '0.0000',
            },
        ],
    },
]


class MyTest(unittest.TestCase):

    def testGetPacketLossAndOutOfOrder(self):
        """Simplest get_packets_loss_and_out_of_order test."""
        for test_case in getPacketLossAndOutOfOrderTestCases:
            ploss, porder, pdups, rtp_seq_max = (
                rtpcap.get_packets_loss_and_out_of_order(
                    test_case['rtp_seq_prev'],
                    test_case['rtp_seq_list']))
            msg = 'unittest failed: %s' % test_case['name']
            self.assertEqual(test_case['ploss'], ploss, msg=msg)
            self.assertEqual(test_case['porder'], porder, msg=msg)
            self.assertEqual(test_case['pdups'], pdups, msg=msg)
            self.assertEqual(test_case['rtp_seq_max'], rtp_seq_max, msg=msg)

    def testAnalyzeVideoFrame(self):
        """Simplest analize_video_frame tests."""
        for test_case in analyzeVideoFrameTestCases:
            ip_src = 'ip_src'
            rtp_ssrc = 'rtp_ssrc'
            parsed_rtp_list = {
                'ip_src': {
                    'rtp_ssrc': test_case['parsed_rtp_list']
                }
            }
            out_data = rtpcap.analyze_video_frame(
                parsed_rtp_list, ip_src, rtp_ssrc)
            msg = 'unittest failed: %s' % test_case['name']
            self.assertEqual(test_case['out_data'], out_data, msg=msg)

    def testParseUdpConnections(self):
        """Simplest analize_video_frame tests."""
        for test_case in parseUdpConnectionsTestCases:
            udp_connections = rtpcap.parse_udp_connections(test_case['tshark'])
            msg = 'unittest failed: %s' % test_case['name']
            self.assertEqual(test_case['udp_connections'], udp_connections,
                             msg=msg)


if __name__ == '__main__':
    unittest.main()
