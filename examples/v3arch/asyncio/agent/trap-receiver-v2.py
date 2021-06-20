
from pysnmp.hlapi.v3arch.asyncio.TrapListener import *
from pysnmp.hlapi.v1arch.asyncore import *
from pysnmp.smi import view
from pysnmp.proto.rfc1902 import ObjectName
import time

snmpengine = SnmpEngine()
community_string = 'public'

snmpengine1 = SnmpEngine()

protocol = ['v2c', 'v3']

authentication_method = ['no-auth-no-priv', 'auth-no-priv', 'auth-priv']

authentication_protocol = ['md5', 'sha', 'sha-224', 'sha-256', 'sha-384', 'sha-512']

authentication_passphrase = 'testauth234'

privacy_protocol = ['aes', 'des']

privacy_passphrase = 'testpriv234'

server_address = 'localhost'

n_var1 = NotificationType(ObjectIdentity('SNMPv2-MIB', 'coldStart'))
n_var2 = NotificationType(ObjectIdentity('SNMPv2-MIB', 'warmStart'))

auth_detailsv2 = CommunityData('public')
server_port = 1015

def send_notifications(snmpengine, auth_details, server_address, server_port, notification_var):
    iterator = sendNotification(
        snmpengine,
        auth_details,
        UdpTransportTarget((server_address, server_port)),
        'trap',
        notification_var, lookupMib=True)


    snmpengine.transportDispatcher.runDispatcher()




trap_listener = start_listener(
    snmpengine1, server_address=server_address, server_port=server_port,
    protocol='v2c'
)

check_printed_output = [
    'SNMPv2-MIB::sysUpTime.0 = 0',
    'SNMPv2-MIB::snmpTrapOID.0 = SNMPv2-MIB::coldStart']

time.sleep(3)



send_notifications(snmpengine=snmpengine, auth_details=auth_detailsv2, server_address=server_address,
server_port=server_port, notification_var=n_var1)

time.sleep(5)

trap_list = trap_listener.getTrapList()

assert len(trap_list) == 1


for each_trap in trap_list:

    assert [each_entry['fully_printed'] for each_entry in each_trap['varBindList']] == check_printed_output



time.sleep(5)

trap_listener.stop_listener()

snmpengine.transportDispatcher.closeDispatcher()