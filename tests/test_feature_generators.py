"""
Right now just manually check individual packets to see if they're parsed correctly
"""

from generate_features import *


def test_gen_http_request_features(http_request_packet):
    result = gen_http_request_features(http_request_packet)
    pass


def test_gen_http_response_features(http_response_packet):
    result = gen_http_response_features(http_response_packet)
    pass


def test_gen_dns_request_features(dns_request_packet):
    result = gen_dns_request_features(dns_request_packet)
    pass


def test_gen_dns_response_features(dns_response_packet):
    result = gen_dns_response_features(dns_response_packet)
    pass