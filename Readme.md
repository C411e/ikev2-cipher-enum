# ikev2-cipher-enum
- Enumerates ikev2 ciphers from a VPN gateway
- The code is dirty but it works
- Based on the ikev2.py implementation of scapy https://github.com/secdev/scapy/blob/master/scapy/contrib/ikev2.py
- Gateways with cookies are not supported right now


## Installation

    git clone git@github.com:C411e/ikev2-scanner.git
    cd ikev2-scanner
    pip3 install -r requirements.txt

## Parameters

	-h, --help        show this help message and exit
	-t SCAN_TYPE, --scan_type SCAN_TYPE
	                  the scan_type. Possible values: all, weak, custom
	-H HOST, --host HOST  the target ip
	-p PORT, --port PORT  the target port (Default: 500)
	-e ENC_ALGS, --enc_algs ENC_ALGS
	                  Encryption Algorithms
	-f PRF_ALGS, --prf_algs PRF_ALGS
	                  PRF Algorithms
	-i INT_ALGS, --int_algs INT_ALGS
	                  Integrity Algorithms
	-g GROUP_ALGS, --group_algs GROUP_ALGS
	                  DH Group Algorithms
	-d, --debug           Enable Debugging
	-st SEND_TIMEOUT, --send_timeout SEND_TIMEOUT
	                  Timeout between packets to send
	-rt RECEIVE_TIMEOUT, --receive_timeout RECEIVE_TIMEOUT
	                  Timeout to wait for a packet to receive (Default: 3
	                  seconds)



## Algorithms List

### Encryption Algorithms:
    "DES-IV64" : 1
    "DES" : 2
    "3DES" : 3
    "RC5" : 4
    "IDEA" : 5
    "CAST" : 6
    "Blowfish" : 7
    "3IDEA" : 8
    "DES-IV32" : 9
    "AES-CBC" : 12
    "AES-CTR" : 13
    "AES-CCM-8" : 14
    "AES-CCM-12" : 15
    "AES-CCM-16" : 16
    "AES-GCM-8ICV" : 18
    "AES-GCM-12ICV" : 19
    "AES-GCM-16ICV" : 20
    "Camellia-CBC" : 23
    "Camellia-CTR" : 24
    "Camellia-CCM-8ICV" : 25
    "Camellia-CCM-12ICV" : 26
    "Camellia-CCM-16ICV" : 27

### PRF Algorithms
    "PRF_HMAC_MD5":1
    "PRF_HMAC_SHA1":2
    "PRF_HMAC_TIGER":3
    "PRF_AES128_XCBC":4
    "PRF_HMAC_SHA2_256":5
    "PRF_HMAC_SHA2_384":6
    "PRF_HMAC_SHA2_512":7
    "PRF_AES128_CMAC":8


### Integrity Algorithms
    "HMAC-MD5-96": 1
    "HMAC-SHA1-96": 2
    "DES-MAC": 3
    "KPDK-MD5": 4
    "AES-XCBC-96": 5
    "HMAC-MD5-128": 6
    "HMAC-SHA1-160": 7
    "AES-CMAC-96": 8
    "AES-128-GMAC": 9
    "AES-192-GMAC": 10
    "AES-256-GMAC": 11
    "SHA2-256-128": 12
    "SHA2-384-192": 13
    "SHA2-512-256": 14

### Group Algorithms
    "768MODPgr"  : 1
    "1024MODPgr" : 2
    "1536MODPgr" : 5
    "2048MODPgr" : 14
    "3072MODPgr" : 15
    "4096MODPgr" : 16
    "6144MODPgr" : 17
    "8192MODPgr" : 18
    "256randECPgr" : 19
    "384randECPgr" : 20
    "521randECPgr" : 21
    "1024MODP160POSgr"  : 22
    "2048MODP224POSgr"  : 23
    "2048MODP256POSgr"  : 24
    "192randECPgr" : 25
    "224randECPgr" : 26

## Examples

Probes a host using weak ciphers:

	ikev2-cipher-enum.py -H 192.168.2.1 -t weak

Probes a host using a custom set of ciphers:

	ikev2-cipher-enum.py -H 192.168.2.1 -t custom -e 1,2 -f 1,2,3 -i 2 - g 1,2


Example Output:

    sudo python3 ikev2-cipher-enum.py -H 1.1.1.1 -t all 
    Start scanning 1.1.1.1:500 sending 89600 proposals/packets...
    on 16371: Accepted :AES-CBC128 PRF_HMAC_SHA1 HMAC-SHA1-96 1536MODPgr
    on 16371: Accepted :AES-CBC192 PRF_HMAC_SHA1 HMAC-SHA1-96 1536MODPgr
    on 16371: Accepted :AES-CBC256 PRF_HMAC_SHA1 HMAC-SHA1-96 1536MODPgr
    on 16372: Accepted :AES-CBC256 PRF_HMAC_SHA1 HMAC-SHA1-96 2048MODPgr
    on 17204: Accepted :AES-CBC128 PRF_HMAC_SHA2_256 SHA2-256-128 2048MODPgr
    on 17684: Accepted :AES-CBC256 PRF_HMAC_SHA2_512 SHA2-512-256 2048MODPgr
    |████████▏                               | ▂▂▄ 18171/89600 [20%] in 12:45:51 (~50:10:28, 0.4/s)


## Todos
- Add cookie support (Send cookie back in an additional packet)
- Multi-Threading