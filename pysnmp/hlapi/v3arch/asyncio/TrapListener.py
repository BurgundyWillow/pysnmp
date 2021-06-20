from pysnmp.hlapi.v3arch.asyncio.ntfrcv import TrapListener
from pysnmp.entity.engine import SnmpEngine







def start_listener(snmpEngine, server_address = 'localhost', server_port = 161, timeout=1.5, protocol = 'v2c', authentication_method = None, auth_protocol = None, auth_passphrase = None, priv_protocol = None, priv_passphrase = None, cbFunc = None, mib_load_paths = [],
mib_names_to_load = []):

    """
    Starts the SNMP Trap Listener to receive message from a server.

    Callback function takes a list argument usually created by the function when receiving traps.

    Example:

        def cbFunc(list_result):
            for each_result in list_result[0]:
                print(each_result['fully_printed'])

    :param snmpEngine: Engine object used to communicate with the User, and Mib Models
    :type snmpEngine: SnmpEngine
    :param server_address: Address for the listener to bind to.
    :type server_address: str
    :param server_port: Server Port to open for listening
    :type server_port: int
    :param timeout: The timer resolution and the delay before closing the socket.
    :type timeout: int
    :param protocol: The SNMP Protocol Version
    :type protocol: 'v1' | 'v2' | 'v2c'| 'v3'
    :param authentication_method: Authentication method (for SNMPv3)
    :type authentication_method: 'no-auth-no-priv' | 'auth-no-priv' | 'auth-priv'
    :param auth_protocol: Authentication protocols for SNMPv3
    :type auth_protocol: 'md5' | 'sha' | 'sha-224' | 'sha-256' | sha-384' | 'sha-512'
    :param auth_passphrase: Authentication passphrase to be accompanied for use with Authentication Protocols
    :type auth_passphrase: str
    :param priv_protocol: Privacy protocol for use with SNMPv3
    :type priv_protocol: 'aes-128' | 'aes-256' | 'aes-192' | 'aes-192-blue-menthal' | 'aes-256-blue-menthal' | 'des-3' | 'des'
    :param priv_passphrase: Privacy passphrase for use wtih SNMPv3
    :type priv_passphrase: str
    :param cbFunc: Callback function taking a dictionary argument. Can be used to invoke a callback for each trap received 
    :type cbFunc: Function(dict[str:obj])
    :param mib_load_paths: Load paths as per the conventions of your specific operating system
    :type mib_load_paths; [str]
    :param mib_names_to_load: Names of compiled mib files to load
    :type mib_names_to_load: [str]

    :return: None
    :rtype: None

    """

    trap_listener = TrapListener(snmpEngine=snmpEngine, protocol=protocol, authentication_method=authentication_method, auth_protocol=auth_protocol,auth_passphrase=auth_passphrase, priv_protocol=priv_protocol, priv_passphrase=priv_passphrase,
    cbSec=cbFunc)

    trap_listener.loadMibResolver(mib_load_paths=mib_load_paths, mib_names=mib_names_to_load)

    trap_listener.start_listener(server_address=server_address, server_port=server_port,timeout=timeout)

    return trap_listener

def get_trap_data_from_listener(trap_listener):

    """

    Get a list of traps that have been received until the moment the user calls this function.

    This is the same list that is given to the callback function passed to start_listener

    :param trap_listener: The trap listener that has been previously created through start_listener
    :type trap_listener: TrapListener

    :return: list[Any]
    
    """

    return trap_listener.getTrapList()

def stop_trap_listener(trap_listener):

    """

    Stop the trap listener and close open channels

    :param trap_listener: The trap listener created by start_listener
    :type trap_listener: TrapListener

    :return: None 

    """

    trap_listener.stop_listener()

