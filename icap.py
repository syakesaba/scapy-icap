#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Base Code Author : Steeve Barbeau, Luca Invernizzi
# This program is published under a GPLv2 license

from scapy.all import TCP
from scapy.all import bind_layers
from scapy.all import Packet
from scapy.all import StrField

def _canonicalize_header(name):
    ''' Takes a header key (i.e., "Host" in "Host: www.google.com",
        and returns a canonical representation of it '''
    return name.strip().lower()


def _parse_headers(s):
    ''' Takes a ICAP packet, and returns a tuple containing:
      - the first line (e.g., "REQMOD ...")
      - the headers in a dictionary
      - the body '''
    try:
        headers, body = s.split("\r\n\r\n", 1)
    except:
        headers = s
        body = ''
    headers = headers.split("\r\n")
    first_line, headers = headers[0].strip(), headers[1:]
    headers_found = {}
    for header_line in headers:
        try:
            key, value = header_line.split(':', 1)  # @UnusedVariable
        except:
            continue
        headers_found[_canonicalize_header(key)] = header_line.strip()
    return first_line, headers_found, body


def _dissect_headers(obj, s):
    ''' Takes a ICAP packet as the string s, and populates the scapy layer obj
        (either ICAPResponse or ICAPRequest). Returns the first line of the
        ICAP packet, and the body
    '''
    first_line, headers, body = _parse_headers(s)
    for f in obj.fields_desc:
        canonical_name = _canonicalize_header(f.name)
        try:
            header_line = headers[canonical_name]
        except:
            continue
        key, value = header_line.split(':', 1)  # @UnusedVariable
        obj.setfieldval(f.name,  value.strip())
        del headers[canonical_name]
    if headers:
        obj.setfieldval(
            'AdditionalHeaders', '\r\n'.join(headers.values()) + '\r\n')
    return first_line, body


def _self_build(obj, field_pos_list=None):
    ''' Takse an ICAPRequest or ICAPResponse object, and creates its internal
    scapy representation as a string. That is, generates the ICAP
    packet as a string '''
    p = ""
    for f in obj.fields_desc:
        val = obj.getfieldval(f.name)
        if not val:
            continue
        val += '\r\n'
        if f.name in ['Method', 'AdditionalHeaders', 'StatusLine']:
            p = f.addfield(obj, p, val)
        else:
            p = f.addfield(obj, p, "%s: %s" % (f.name, val))
    return p


class ICAPRequest(Packet):

    name = "ICAP Request"

    fields_desc = [StrField("Method", None, fmt="H"),
                StrField("Cache-Control", None, fmt="H"),
                StrField("Connection", None, fmt="H"),
                StrField("Date", None, fmt="H"),
                StrField("Pragma", None, fmt="H"),
                StrField("Trailer", None, fmt="H"),
                StrField("Upgrade", None, fmt="H"),
                StrField("Expires", None, fmt="H"),
                StrField("Encapsulated", None, fmt="H"),
                StrField("Host", None, fmt="H"),
                StrField("User-Agent", None, fmt="H"),
                StrField("Referer", None, fmt="H"),
                StrField("Authorization", None, fmt="H"),
                StrField("From", None, fmt="H"),
                StrField("Allow", None, fmt="H"),
                StrField("Preview", None, fmt="H"),
                StrField("AdditionalHeaders", None, fmt="H")]

    def do_dissect(self, s):
        ''' From the ICAP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        self.setfieldval('Method', first_line)
        return body

    def self_build(self, field_pos_list=None):
        ''' Generate the ICAP packet string (the oppposite of do_dissect) '''
        return _self_build(self, field_pos_list)


class ICAPResponse(Packet):

    name = "ICAP Response"

    fields_desc = [StrField("StatusLine", None, fmt="H"),
                StrField("Cache-Control", None, fmt="H"),
                StrField("Connection", None, fmt="H"),
                StrField("Date", None, fmt="H"),
                StrField("Pragma", None, fmt="H"),
                StrField("Trailer", None, fmt="H"),
                StrField("Upgrade", None, fmt="H"),
                StrField("Expires", None, fmt="H"),
                StrField("Encapsulated", None, fmt="H"),
                StrField("Server", None, fmt="H"),
                StrField("IsTag", None, fmt="H"),
                StrField("Methods", None, fmt="H"),
                StrField("Service", None, fmt="H"),
                StrField("Opt-body-type", None, fmt="H"),
                StrField("Max-Connections", None, fmt="H"),
                StrField("Options-TTL", None, fmt="H"),
                StrField("Service-ID", None, fmt="H"),
                StrField("Allow", None, fmt="H"),
                StrField("Preview", None, fmt="H"),
                StrField("Transfer-Preview", None, fmt="H"),
                StrField("Transfer-Ignore", None, fmt="H"),
                StrField("Transfer-Complete", None, fmt="H"),
                StrField("AdditionalHeaders", None, fmt="H")]

    def do_dissect(self, s):
        ''' From the ICAP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        self.setfieldval('StatusLine', first_line)
        return body

    def self_build(self, field_pos_list=None):
        ''' From the ICAP packet string, populate the scapy object '''
        return _self_build(self, field_pos_list)


class ICAP(Packet):

    name = "ICAP"

    def do_dissect(self, s):
        return s

    def guess_payload_class(self, payload):
        ''' Decides if the payload is an ICAP Request or Response, or
            something else '''
        try:
            icap_req = payload[:payload.index("\r\n")]
            s1,s2,s3 = icap_req.split(" ") # @UnusedVariable s2
        except:
            return Packet.guess_payload_class(self, payload)
        icap_versions = ["ICAP/0.9","ICAP/1.0","ICAP/1.1"]
        for icap_version in icap_versions:
            if s3 == icap_version:
                return ICAPRequest
            if s1 == icap_version:
                return ICAPResponse
        return Packet.guess_payload_class(self, payload)

#bind_layers(TCP, ICAP)
#bind_layers(TCP, ICAP)
bind_layers(TCP, ICAP, dport=1344)
bind_layers(TCP, ICAP, sport=1344)
