
from pysnmp.hlapi.v3arch.asyncio.TrapListener import *
from pysnmp.hlapi.v3arch.asyncore import *
from pysnmp.smi import view
from pysnmp.proto.rfc1902 import ObjectName
import time
from pysnmp.hlapi.v3arch.auth import *
from pysnmp.entity.config import *

snmpengine = SnmpEngine()
community_string = 'public'

snmpengine1 = SnmpEngine()

authentication_method = ['no-auth-no-priv', 'auth-no-priv', 'auth-priv']

authentication_protocol = ['md5', 'sha', 'sha-224', 'sha-256', 'sha-384', 'sha-512']

auth_keyword_config = [USM_AUTH_HMAC96_MD5, USM_AUTH_HMAC96_SHA, USM_AUTH_HMAC128_SHA224,
USM_AUTH_HMAC192_SHA256, USM_AUTH_HMAC256_SHA384,USM_AUTH_HMAC384_SHA512]


authentication_passphrase = 'testsha234'

privacy_protocol = ['aes-128','aes-256','aes-192','aes-192-blue-menthal','aes-256-blue-menthal','des-3','des']

privacy_config = [USM_PRIV_CFB128_AES, USM_PRIV_CFB256_AES, USM_PRIV_CFB192_AES,
USM_PRIV_CFB192_AES_BLUMENTHAL, USM_PRIV_CFB256_AES_BLUMENTHAL, USM_PRIV_CBC168_3DES,
USM_PRIV_CBC56_DES]

privacy_passphrase = 'testaes234'

server_address = 'localhost'

n_var1 = NotificationType(ObjectIdentity('SNMPv2-MIB', 'coldStart'))
n_var2 = NotificationType(ObjectIdentity('SNMPv2-MIB', 'warmStart'))

server_port = 1015

def send_notifications(snmpengine, auth_details, server_address, server_port, notification_var):
    iterator = sendNotification(
        snmpengine,
        auth_details,
        UdpTransportTarget((server_address, server_port)),
        ContextData(),
        'trap',
        notification_var, lookupMib=True)

    snmpengine.transportDispatcher.runDispatcher()
    





check_printed_output = [
    'SNMPv2-MIB::sysUpTime.0 = 0',
    'SNMPv2-MIB::snmpTrapOID.0 = SNMPv2-MIB::coldStart']

time.sleep(3)



def check_v3_traps(user_name = 'testuser', auth_protocol = None, priv_protocol = None, auth_proto_config = None, 
priv_proto_config = None, auth_proto_method = None):

    if auth_protocol is None:
        auth_pass = None
    else:
        auth_pass = authentication_passphrase
    
    if priv_protocol is None:
        priv_pass = None
    else:
        priv_pass = privacy_passphrase

    auth_detailsv2 = UsmUserData(userName=user_name, 
    authKey=auth_pass, privKey=priv_pass, authProtocol=auth_proto_config,
    privProtocol=priv_proto_config)
    
    trap_listener = start_listener(
    snmpengine1, server_address=server_address, server_port=server_port,
    protocol='v3', authentication_method = auth_proto_method, auth_protocol=auth_protocol,
    auth_passphrase=auth_pass ,priv_protocol=priv_protocol, priv_passphrase=priv_pass
)

    time.sleep(10)
    
    send_notifications(snmpengine=snmpengine, auth_details=auth_detailsv2, server_address=server_address,
    server_port=server_port, notification_var=n_var1)
    
    time.sleep(5)

    trap_list = trap_listener.getTrapList()


    time.sleep(5)

    assert len(trap_list) >= 1
    print(trap_list)

    for each_trap in trap_list:

        assert [each_entry['fully_printed'] for each_entry in each_trap['varBindList']] == check_printed_output



    time.sleep(5)

    trap_listener.stop_listener()

    time.sleep(10)
    



auth_proto_method = 'auth-priv'


for (each_auth_proto, each_auth_proto_config) in zip(authentication_protocol, auth_keyword_config):
    for (each_priv_proto, each_priv_proto_config) in zip(privacy_protocol, privacy_config):

    
        check_v3_traps(auth_protocol=each_auth_proto, priv_protocol=each_priv_proto,
        auth_proto_config=each_auth_proto_config, priv_proto_config=each_priv_proto_config,
        auth_proto_method=auth_proto_method)