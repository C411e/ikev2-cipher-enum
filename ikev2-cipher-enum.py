#!/usr/bin/env python


########################
# This stuff is the implementation of IKEv2 from ikev2.py.
# go to line 473 to see the actual scanning script


# Additional imports
import time
import datetime
import argparse
from scapy.layers import *
from scapy.sendrecv import *
from alive_progress import alive_bar


# http://trac.secdev.org/scapy/ticket/353
# scapy.contrib.description = IKEv2
# scapy.contrib.status = loads

import logging
import struct
import os
## Modified from the original ISAKMP code by Yaron Sheffer <yaronf.ietf@gmail.com>, June 2010.

from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import IP,UDP
from scapy.layers.isakmp import ISAKMP
from scapy.sendrecv import sr
from scapy.all import RandString

# see http://www.iana.org/assignments/ikev2-parameters%20for%20details
IKEv2AttributeTypes= { "Encryption":    (1, { "DES-IV64"  : 1,
                                                "DES" : 2,
                                                "3DES" : 3,
                                                "RC5" : 4,
                                                "IDEA" : 5,
                                                "CAST" : 6,
                                                "Blowfish" : 7,
                                                "3IDEA" : 8,
                                                "DES-IV32" : 9,
                                                "AES-CBC" : 12,
                                                "AES-CTR" : 13,
                                                "AES-CCM-8" : 14,
                                                "AES-CCM-12" : 15,
                                                "AES-CCM-16" : 16,
                                                "AES-GCM-8ICV" : 18,
                                                "AES-GCM-12ICV" : 19,
                                                "AES-GCM-16ICV" : 20,
                                                "Camellia-CBC" : 23,
                                                "Camellia-CTR" : 24,
                                                "Camellia-CCM-8ICV" : 25,
                                                "Camellia-CCM-12ICV" : 26,
                                                "Camellia-CCM-16ICV" : 27,
                                        }, 0),
                         "PRF":            (2, {"PRF_HMAC_MD5":1,
                                                "PRF_HMAC_SHA1":2,
                                                "PRF_HMAC_TIGER":3,
                                                "PRF_AES128_XCBC":4,
                                                "PRF_HMAC_SHA2_256":5,
                                                "PRF_HMAC_SHA2_384":6,
                                                "PRF_HMAC_SHA2_512":7,
                                                "PRF_AES128_CMAC":8,
                                       }, 0),
                         "Integrity":    (3, { "HMAC-MD5-96": 1,
                                                "HMAC-SHA1-96": 2,
                                                "DES-MAC": 3,
                                                "KPDK-MD5": 4,
                                                "AES-XCBC-96": 5,
                                                "HMAC-MD5-128": 6,
                                                "HMAC-SHA1-160": 7,
                                                "AES-CMAC-96": 8,
                                                "AES-128-GMAC": 9,
                                                "AES-192-GMAC": 10,
                                                "AES-256-GMAC": 11,
                                                "SHA2-256-128": 12,
                                                "SHA2-384-192": 13,
                                                "SHA2-512-256": 14,
                                        }, 0),
                         "GroupDesc":     (4, { "768MODPgr"  : 1,
                                                "1024MODPgr" : 2,
                                                "1536MODPgr" : 5,
                                                "2048MODPgr" : 14,
                                                "3072MODPgr" : 15,
                                                "4096MODPgr" : 16,
                                                "6144MODPgr" : 17,
                                                "8192MODPgr" : 18,
                                                "256randECPgr" : 19,
                                                "384randECPgr" : 20,
                                                "521randECPgr" : 21,
                                                "1024MODP160POSgr"  : 22,
                                                "2048MODP224POSgr"  : 23,
                                                "2048MODP256POSgr"  : 24,
                                                "192randECPgr" : 25,
                                                "224randECPgr" : 26,
                                        }, 0),
                         "Extended Sequence Number":       (5, {"No ESN":     0,
                                                 "ESN":   1,  }, 0),
                         }

IKEv2NotifyMessageTypes = {
  1 : "UNSUPPORTED_CRITICAL_PAYLOAD",
  4 : "INVALID_IKE_SPI",
  5 : "INVALID_MAJOR_VERSION",
  7 : "INVALID_SYNTAX",
  9 : "INVALID_MESSAGE_ID",
  11 : "INVALID_SPI",
  14 : "NO_PROPOSAL_CHOSEN",
  17 : "INVALID_KE_PAYLOAD",
  24 : "AUTHENTICATION_FAILED",
  34 : "SINGLE_PAIR_REQUIRED",
  35 : "NO_ADDITIONAL_SAS",
  36 : "INTERNAL_ADDRESS_FAILURE",
  37 : "FAILED_CP_REQUIRED",
  38 : "TS_UNACCEPTABLE",
  39 : "INVALID_SELECTORS",
  40 : "UNACCEPTABLE_ADDRESSES",
  41 : "UNEXPECTED_NAT_DETECTED",
  42 : "USE_ASSIGNED_HoA",
  43 : "TEMPORARY_FAILURE",
  44 : "CHILD_SA_NOT_FOUND",
  45 : "INVALID_GROUP_ID",
  46 : "AUTHORIZATION_FAILED",
  16384 : "INITIAL_CONTACT",
  16385 : "SET_WINDOW_SIZE",
  16386 : "ADDITIONAL_TS_POSSIBLE",
  16387 : "IPCOMP_SUPPORTED",
  16388 : "NAT_DETECTION_SOURCE_IP",
  16389 : "NAT_DETECTION_DESTINATION_IP",
  16390 : "COOKIE",
  16391 : "USE_TRANSPORT_MODE",
  16392 : "HTTP_CERT_LOOKUP_SUPPORTED",
  16393 : "REKEY_SA",
  16394 : "ESP_TFC_PADDING_NOT_SUPPORTED",
  16395 : "NON_FIRST_FRAGMENTS_ALSO",
  16396 : "MOBIKE_SUPPORTED",
  16397 : "ADDITIONAL_IP4_ADDRESS",
  16398 : "ADDITIONAL_IP6_ADDRESS",
  16399 : "NO_ADDITIONAL_ADDRESSES",
  16400 : "UPDATE_SA_ADDRESSES",
  16401 : "COOKIE2",
  16402 : "NO_NATS_ALLOWED",
  16403 : "AUTH_LIFETIME",
  16404 : "MULTIPLE_AUTH_SUPPORTED",
  16405 : "ANOTHER_AUTH_FOLLOWS",
  16406 : "REDIRECT_SUPPORTED",
  16407 : "REDIRECT",
  16408 : "REDIRECTED_FROM",
  16409 : "TICKET_LT_OPAQUE",
  16410 : "TICKET_REQUEST",
  16411 : "TICKET_ACK",
  16412 : "TICKET_NACK",
  16413 : "TICKET_OPAQUE",
  16414 : "LINK_ID",
  16415 : "USE_WESP_MODE",
  16416 : "ROHC_SUPPORTED",
  16417 : "EAP_ONLY_AUTHENTICATION",
  16418 : "CHILDLESS_IKEV2_SUPPORTED",
  16419 : "QUICK_CRASH_DETECTION",
  16420 : "IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
  16421 : "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED",
  16422 : "IKEV2_MESSAGE_ID_SYNC",
  16423 : "IPSEC_REPLAY_COUNTER_SYNC",
  16424 : "SECURE_PASSWORD_METHODS",
  16425 : "PSK_PERSIST",
  16426 : "PSK_CONFIRM",
  16427 : "ERX_SUPPORTED",
  16428 : "IFOM_CAPABILITY",
  16429 : "SENDER_REQUEST_ID",
  16430 : "IKEV2_FRAGMENTATION_SUPPORTED",
  16431 : "SIGNATURE_HASH_ALGORITHMS",
  16432 : "CLONE_IKE_SA_SUPPORTED",
  16433 : "CLONE_IKE_SA"
}

IKEv2CertificateEncodings = {
  1 : "PKCS #7 wrapped X.509 certificate",
  2 : "PGP Certificate",
  3 : "DNS Signed Key",
  4 : "X.509 Certificate - Signature",
  6 : "Kerberos Token",
  7 : "Certificate Revocation List (CRL)",
  8 : "Authority Revocation List (ARL)",
  9 : "SPKI Certificate",
  10 : "X.509 Certificate - Attribute",
  11 : "Raw RSA Key",
  12 : "Hash and URL of X.509 certificate",
  13 : "Hash and URL of X.509 bundle"
}

# the name 'IKEv2TransformTypes' is actually a misnomer (since the table
# holds info for all IKEv2 Attribute types, not just transforms, but we'll
# keep it for backwards compatibility... for now at least
IKEv2TransformTypes = IKEv2AttributeTypes

IKEv2TransformNum = {}
for n in IKEv2TransformTypes:
    val = IKEv2TransformTypes[n]
    tmp = {}
    for e in val[1]:
        tmp[val[1][e]] = e
    IKEv2TransformNum[val[0]] = tmp

IKEv2Transforms = {}
for n in IKEv2TransformTypes:
    IKEv2Transforms[IKEv2TransformTypes[n][0]]=n

del(n)
del(e)
del(tmp)
del(val)

# Note: Transform and Proposal can only be used inside the SA payload
IKEv2_payload_type = ["None", "", "Proposal", "Transform"]

IKEv2_payload_type.extend([""] * 29)
IKEv2_payload_type.extend(["SA","KE","IDi","IDr", "CERT","CERTREQ","AUTH","Nonce","Notify","Delete",
                       "VendorID","TSi","TSr","Encrypted","CP","EAP"])

IKEv2_exchange_type = [""] * 34
IKEv2_exchange_type.extend(["IKE_SA_INIT","IKE_AUTH","CREATE_CHILD_SA",
                        "INFORMATIONAL", "IKE_SESSION_RESUME"])


class IKEv2_class(Packet):
    def guess_payload_class(self, payload):
        np = self.next_payload
        logging.debug("For IKEv2_class np=%d" % np)
        if np == 0:
            return conf.raw_layer
        elif np < len(IKEv2_payload_type):
            pt = IKEv2_payload_type[np]
            logging.debug(globals().get("IKEv2_payload_%s" % pt, IKEv2_payload))
            return globals().get("IKEv2_payload_%s" % pt, IKEv2_payload)
        else:
            return IKEv2_payload


class IKEv2(IKEv2_class): # rfc4306
    name = "IKEv2"
    fields_desc = [
        StrFixedLenField("init_SPI","",8),
        StrFixedLenField("resp_SPI","",8),
        ByteEnumField("next_payload",0,IKEv2_payload_type),
        XByteField("version",0x20), # IKEv2, right?
        ByteEnumField("exch_type",0,IKEv2_exchange_type),
        FlagsField("flags",0, 8, ["res0","res1","res2","Initiator","Version","Response","res6","res7"]),
        IntField("id",0),
        IntField("length",None)
        ]

    def guess_payload_class(self, payload):
        if self.flags & 1:
            return conf.raw_layer
        return IKEv2_class.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, IKEv2):
            if other.init_SPI == self.init_SPI:
                return 1
        return 0
    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = p[:24]+struct.pack("!I",len(p))+p[28:]
        return p


class IKEv2_Key_Length_Attribute(IntField):
    # We only support the fixed-length Key Length attribute (the only one currently defined)
    def __init__(self, name):
        IntField.__init__(self, name, 0x800E0000)

    def i2h(self, pkt, x):
        return IntField.i2h(self, pkt, x & 0xFFFF)

    def h2i(self, pkt, x):
        return IntField.h2i(self, pkt, x if x !=None else 0 | 0x800E0000)

class IKEv2_payload_Transform(IKEv2_class):
    name = "IKE Transform"
    fields_desc = [
        ByteEnumField("next_payload",None,{0:"last", 3:"Transform"}),
        ByteField("res",0),
        ShortField("length",8),
        ByteEnumField("transform_type",None,IKEv2Transforms),
        ByteField("res2",0),
        MultiEnumField("transform_id",None,IKEv2TransformNum,depends_on=lambda pkt:pkt.transform_type,fmt="H"),
        ConditionalField(IKEv2_Key_Length_Attribute("key_length"), lambda pkt: pkt.length > 8),
    ]

class IKEv2_payload_Proposal(IKEv2_class):
    name = "IKEv2 Proposal"
    fields_desc = [
        ByteEnumField("next_payload",None,{0:"last", 2:"Proposal"}),
        ByteField("res",0),
        FieldLenField("length",None,"trans","H", adjust=lambda pkt,x:x+8),
        ByteField("proposal",1),
        ByteEnumField("proto",1,{1:"IKEv2"}),
        FieldLenField("SPIsize",None,"SPI","B"),
        ByteField("trans_nb",None),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        PacketLenField("trans",conf.raw_layer(),IKEv2_payload_Transform,length_from=lambda x:x.length-8),
        ]


class IKEv2_payload(IKEv2_class):
    name = "IKEv2 Payload"
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        FlagsField("flags",0, 8, ["critical","res1","res2","res3","res4","res5","res6","res7"]),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]


class IKEv2_payload_VendorID(IKEv2_class):
    name = "IKEv2 Vendor ID"
    overload_fields = { IKEv2: { "next_payload":43 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"vendorID","H", adjust=lambda pkt,x:x+4),
        StrLenField("vendorID","",length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_Delete(IKEv2_class):
    name = "IKEv2 Vendor ID"
    overload_fields = { IKEv2: { "next_payload":42 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"vendorID","H", adjust=lambda pkt,x:x+4),
        StrLenField("vendorID","",length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_SA(IKEv2_class):
    name = "IKEv2 SA"
    overload_fields = { IKEv2: { "next_payload":33 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"prop","H", adjust=lambda pkt,x:x+4),
        PacketLenField("prop",conf.raw_layer(),IKEv2_payload_Proposal,length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_Nonce(IKEv2_class):
    name = "IKEv2 Nonce"
    overload_fields = { IKEv2: { "next_payload":40 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_Notify(IKEv2_class):
    name = "IKEv2 Notify"
    overload_fields = { IKEv2: { "next_payload":41 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+8),
        ByteEnumField("proto",None,{0:"Reserved",1:"IKE",2:"AH", 3:"ESP"}),
        FieldLenField("SPIsize",None,"SPI","B"),
        ShortEnumField("type",0,IKEv2NotifyMessageTypes),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        StrLenField("load","",length_from=lambda x:x.length-8),
        ]

class IKEv2_payload_KE(IKEv2_class):
    name = "IKEv2 Key Exchange"
    overload_fields = { IKEv2: { "next_payload":34 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+8),
        ShortEnumField("group", 0, IKEv2TransformTypes['GroupDesc'][1]),
        ShortField("res2", 0),
        StrLenField("load","",length_from=lambda x:x.length-8),
        ]

class IKEv2_payload_IDi(IKEv2_class):
    name = "IKEv2 Identification - Initiator"
    overload_fields = { IKEv2: { "next_payload":35 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+8),
        ByteEnumField("IDtype",1,{1:"IPv4_addr", 2:"FQDN", 3:"Email_addr", 5:"IPv6_addr", 11:"Key"}),
        ByteEnumField("ProtoID",0,{0:"Unused"}),
        ShortEnumField("Port",0,{0:"Unused"}),
#        IPField("IdentData","127.0.0.1"),
        StrLenField("load","",length_from=lambda x:x.length-8),
        ]

class IKEv2_payload_IDr(IKEv2_class):
    name = "IKEv2 Identification - Responder"
    overload_fields = { IKEv2: { "next_payload":36 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+8),
        ByteEnumField("IDtype",1,{1:"IPv4_addr", 2:"FQDN", 3:"Email_addr", 5:"IPv6_addr", 11:"Key"}),
        ByteEnumField("ProtoID",0,{0:"Unused"}),
        ShortEnumField("Port",0,{0:"Unused"}),
#        IPField("IdentData","127.0.0.1"),
        StrLenField("load","",length_from=lambda x:x.length-8),
        ]



class IKEv2_payload_Encrypted(IKEv2_class):
    name = "IKEv2 Encrypted and Authenticated"
    overload_fields = { IKEv2: { "next_payload":46 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_CERTREQ(IKEv2_class):
    name = "IKEv2 Certificate Request"
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"cert_data","H",adjust=lambda pkt,x:x+5),
        ByteEnumField("cert_type",0,IKEv2CertificateEncodings),
        StrLenField("cert_data","",length_from=lambda x:x.length-5),
        ]

class IKEv2_payload_CERT(IKEv2_class):
    name = "IKEv2 Certificate"
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"cert_data","H",adjust=lambda pkt,x:x+5),
        ByteEnumField("cert_type",0,IKEv2CertificateEncodings),
        StrLenField("cert_data","",length_from=lambda x:x.length-5),
        ]

IKEv2_payload_type_overload = {}
for i, payloadname in enumerate(IKEv2_payload_type):
    name = "IKEv2_payload_%s" % payloadname
    if name in globals():
        IKEv2_payload_type_overload[globals()[name]] = {"next_payload": i}

del i, payloadname, name
IKEv2_class._overload_fields = IKEv2_payload_type_overload.copy()

split_layers(UDP, ISAKMP, sport=500)
split_layers(UDP, ISAKMP, dport=500)

bind_layers( UDP,           IKEv2,        dport=500, sport=500) # TODO: distinguish IKEv1/IKEv2

def ikev2scan(ip):
    return sr(IP(dst=ip)/UDP()/IKEv2(init_SPI=RandString(8),
                                      exch_type=34)/IKEv2_payload_SA(prop=IKEv2_payload_Proposal()))

def ikev2build(ip):
    return IP(dst=ip)/UDP()/IKEv2(init_SPI=RandString(8),
                                      exch_type=34)/IKEv2_payload_SA(prop=IKEv2_payload_Proposal(IKEv2_payload_Transform()))



# conf.debug_dissector = 1





############################################################################################################
#########################
### ikev2-cipher-enum ###
#########################
#
#
# Author: c411e
# 10.07.2018
#
# Enumerates ciphers from an ikev2 gateway
#



# List of weak ciphers
weak_enc=[1,2,3,6,7,9] # DES-IV64,DES,3DES,CAST,Blowfish,DES-IV32
weak_prf=[1,2] # HMAC-MD5, HMAC-SHA1
weak_int=[1,2,3,4,5,6,7] # HMAC-MD5-96,HMAC-SHA1-96,DES-MAC,KPDK-MD5,AES-XCBC-96,HMAC-MD5-128,HMAC-SHA1-160
weak_group=[1,2,5] # 768MODPgr,1024MODPgr,1536MODPgr


#  List of all ciphers
all_enc = IKEv2AttributeTypes['Encryption'][1].values()
all_prf = IKEv2AttributeTypes['PRF'][1].values()
all_int = IKEv2AttributeTypes['Integrity'][1].values()
all_group = IKEv2AttributeTypes['GroupDesc'][1].values()



# Returns, if an encryption algorithm has multiple key lengths (128,192,256) like AES-CBC
def get_key_length_attribute(n):
    if n==7 or n==12 or n==13 or n==14 or n==15 or n==16 or n==18 or n==19 or n==20 or n==21 or n==23 or n==24 or n==25 or n==26 or n==27:
        return 1
    else:
        return 0



# Sends a packet and tells us if the proposal was chosen
def send_packet(packet,enc_alg,prf,int_alg,group_alg,key_length):
    str_key = ''
    if debug:
        packet.show()

    # Sleep if timeout is set
    if send_timeout != 0:
        time.sleep(send_timeout)

    response = sr1(packet,verbose=0,timeout=receive_timeout)

    # If we receive a ICMP destination unreachable packet
    if response is not None and response.proto == 1:
        print("Received ICMP Destination unreachable packet. Maybe port is down or blocked by a firewall. Exiting...\n")
        exit(0)

    if response is not None and response.next_payload == 33:

        if key_length != 0:
            str_key += str(key_length)

        # Search up Encryption Algo name
        for enc_alg_name, num in IKEv2AttributeTypes['Encryption'][1].items():
            if num == enc_alg:
                str_enc = enc_alg_name

        # Search up PRF Algo name
        for prf_name, num in IKEv2AttributeTypes['PRF'][1].items():
            if num == prf:
                str_prf =  prf_name

        # Search up Integrity Algo name
        for int_name, num in IKEv2AttributeTypes['Integrity'][1].items():
            if num == int_alg:
                str_int =  int_name

        # Search up DH Group Algo name
        for group_name, num in IKEv2AttributeTypes['GroupDesc'][1].items():
            if num == group_alg:
                str_group = group_name

        print("Accepted :" + str_enc + str_key + ' ' + str_prf + ' ' + str_int + ' ' + str_group)


# Returns the Hex value of the key_length
def get_key_length_value(key_length):
    if key_length == 128:
        return 0x800e0080
    if key_length == 192:
        return 0x800e00c0
    if key_length == 256:
        return 0x800e0100


# Returns the length in bytes of a specific DH-Key-Exchange
def get_group_length(n):
    if n == 1:
        return 96
    if n == 2 or n == 22:
        return 128
    if n == 5:
        return 192
    if n == 14 or n == 23 or n == 24:
        return 256
    if n == 15:
        return 384
    if n == 16:
        return 512
    if n == 17:
        return 768
    if n == 18:
        return 1024
    if n == 19:
        return 32
    if n == 20:
        return 48
    if n == 21:
        return 65
    # TODO Exact value is 521 bits so 1 bit is missing
    if n == 22:
        return 128
    if n == 25:
        return 24
    if n == 26:
        return 28
    return 0



# Builds a packet depending on the Encryption Algorithm Key_Length
# (An additional section (Key Length) is necessary for that)
def build_packet(ip,port,enc_alg,prf,int_alg,group_alg,key_length):

    trans_enc = IKEv2_payload_Transform()
    trans_enc.transform_type = 1
    trans_enc.transform_id = enc_alg

    if key_length:
        trans_enc.length = 12
        trans_enc.key_length = get_key_length_value(key_length)


    trans_prf = IKEv2_payload_Transform()
    trans_prf.transform_type = 2
    trans_prf.transform_id = prf

    trans_int = IKEv2_payload_Transform()
    trans_int.transform_type = 3
    trans_int.transform_id = int_alg

    trans_group = IKEv2_payload_Transform()
    trans_group.transform_type = 4
    trans_group.transform_id = group_alg

    prop=IKEv2_payload_Proposal(trans=trans_enc/trans_prf/trans_int/trans_group)

    packet = IP(dst=ip)/UDP(dport=int(port))/IKEv2(init_SPI=RandString(8),
            exch_type=34,flags=0x08)/IKEv2_payload_SA(prop=prop,next_payload=34)/IKEv2_payload_KE(next_payload=40,group=group_alg,load=RandString(get_group_length(group_alg)))/IKEv2_payload_Nonce(load=RandString(20))

    packet.prop.trans_nb = 4  #   We send four transformsets
    return packet



# Scans an ikev2 gateway using a set of given ciphers
def scan_ikev2(ip,port,enc_list,prf_list,int_list,group_list,debug):

    # Calculate packet count
    enc_packet_count = 0
    for p in enc_list:
        if get_key_length_attribute(p):
            enc_packet_count = enc_packet_count + 3
        else:
            enc_packet_count = enc_packet_count + 1

    packet_count = enc_packet_count * len(prf_list) * len(int_list) * len(group_list)
    print("Start scanning " + ip + ":" + port + " sending " + str(packet_count) + " proposals/packets...\n")

    time_start = time.time()

    with alive_bar(packet_count) as bar:
        # Encryption Algos
        for enc_alg in enc_list:

            # PRF Values
            for prf in prf_list:

                # Integrity Algos
                for int_alg in int_list:

                    # GroupDesc
                    for group_alg in group_list:
                        bar()

                        # If the Encryption Algorithm has multiple key lengths we have to send all
                        if get_key_length_attribute(enc_alg):
                            for key_length in 128,192,256:
                                packet = build_packet(ip,port,enc_alg,prf,int_alg,group_alg,key_length)
                                send_packet(packet,enc_alg,prf,int_alg,group_alg,key_length)

                        else:
                            key_length = 0
                            packet = build_packet(ip,port,enc_alg,prf,int_alg,group_alg,key_length)
                            send_packet(packet,enc_alg,prf,int_alg,group_alg,key_length)


    time_end = time.time()
    time_calculate = time_end - time_start

    print("\n")
    print("Scan finished in " + str(datetime.timedelta(seconds=time_calculate)))

if __name__ == "__main__":

    parser= argparse.ArgumentParser()
    parser.add_argument("-t","--scan_type",action="store",  help='the scan_type. Possible values: all, weak, custom')
    parser.add_argument("-H","--host",action="store",  help='the target ip')
    parser.add_argument("-p","--port",action="store",  help='the target port (Default: 500')
    parser.add_argument('-e',"--enc_algs",action="store",  help='Encryption Algorithms')
    parser.add_argument('-f', "--prf_algs", action="store", help='PRF Algorithms')
    parser.add_argument('-i',"--int_algs", action="store", help='Integrity Algorithms')
    parser.add_argument('-g', "--group_algs",action="store", help='DH Group Algorithms')
    parser.add_argument('-d', "--debug",action="store_true", help='Enable Debugging')
    parser.add_argument('-st', "--send_timeout",action="store", help='Timeout between packets to send')
    parser.add_argument('-rt', "--receive_timeout",action="store", help='Timeout to wait for a packet to receive (Default: 3 seconds)')

    args = parser.parse_args()


    if (args.scan_type == None) | (args.host == None):
        print("Scantype and Target IP are requierd")
        exit(0)
    else:
        scan_type = args.scan_type
        ip = args.host

        if args.port == None:
            port = '500'
        else:
            port = args.port

        if args.debug == None:
            debug = False
        else:
            debug = args.debug

        if args.send_timeout == None:
            send_timeout = 0
        else:
            send_timeout = int(args.send_timeout)
        if args.receive_timeout == None:
            receive_timeout = 3
        else:
            receive_timeout = int(args.receive_timeout)
    if scan_type == "all":
        scan_ikev2(ip,port,all_enc,all_prf,all_int,all_group,debug)

    elif scan_type =="weak":
        scan_ikev2(ip,port,weak_enc,weak_prf,weak_int,weak_group,debug)

    elif scan_type =="custom":
        if args.enc_algs == None or args.prf_algs == None or args.int_algs == None or args.group_algs == None:
            print("For custom mode you have to specify all Proposals (enc_algs,prf_algs,int_algs,group_algs)")
        else:
            enc_algs = list(map(int,args.enc_algs.split(',')))
            prf_algs = list(map(int,args.prf_algs.split(',')))
            int_algs = list(map(int,args.int_algs.split(',')))
            group_algs = list(map(int,args.group_algs.split(',')))
            scan_ikev2(ip,port,enc_algs,prf_algs,int_algs,group_algs,debug)
    else:
        print("Select one of the three possible scan types: all, weak, custom")

    if debug:
        print(args)
