from pysnmp.entity.engine import SnmpEngine
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.rfc3412 import MsgAndPduDispatcher
from pysnmp.proto.mpmod.rfc3412 import SnmpV3MessageProcessingModel
from pysnmp.proto.mpmod.rfc2576 import SnmpV1MessageProcessingModel
from pysnmp.proto.mpmod.rfc2576 import SnmpV2cMessageProcessingModel
from pysnmp.proto.mpmod.rfc3412 import SnmpV3MessageProcessingModel, SNMPv3Message, ScopedPDU, ScopedPduData
from pysnmp.proto.secmod.rfc2576 import SnmpV1SecurityModel
from pysnmp.proto.secmod.rfc2576 import SnmpV2cSecurityModel
from pysnmp.proto.secmod.rfc3414 import SnmpUSMSecurityModel
from pyasn1.codec.ber.decoder import decode
from pysnmp.proto import api
from pysnmp.proto.secmod.rfc7860.auth.hmacsha2 import HmacSha2
from pysnmp.proto.secmod.rfc3414.auth.hmacmd5 import HmacMd5
from pysnmp.proto.secmod.rfc3414.auth.hmacsha import HmacSha
import asyncio
from concurrent import futures
import time

from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters, SnmpUSMSecurityModel
from pysnmp.proto.secmod.rfc3826.priv.aes import Aes
from pysnmp.proto.secmod.rfc3414.priv.des import Des
from pysnmp.smi import builder
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error
from pysnmp.proto.errind import *
import binascii
import asyncio
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
from pysnmp.smi import view
from pysnmp.proto.secmod.eso.priv import aes192,aes256,des3


class TrapListener():

    

    def __init__(self,snmpEngine, auth_passphrase = None, priv_passphrase = None, cbFun=None, cbCtx = None, protocol='v2c',
    authentication_method='no-auth-no-priv', auth_protocol=None, priv_protocol=None, cbSec = None):
        self.snmp_engine = snmpEngine
        self.transporter = None
        self.trap_in_session = []
        self.protocol = protocol
        self.auth = authentication_method
        self.authProtocol = auth_protocol
        self.privProtocol = priv_protocol
        self.authPassphrase = auth_passphrase
        self.privPassphrase = priv_passphrase
        self.main_loop = asyncio.get_event_loop()
        self.execution_future = None
        self.thread_for_executing = futures.ThreadPoolExecutor(max_workers=2)
        self.cbSec = cbSec
        self.use_auth_as_init = True
        if self.auth == 'auth-no-priv' or self.auth == 'auth-priv':
            if auth_protocol == 'md5':
                self.authenticator = HmacMd5
                self.auth_proto = HmacMd5.SERVICE_ID
                self.use_auth_as_init = False
            elif auth_protocol == 'sha-128' or auth_protocol == 'sha':
                self.authenticator = HmacSha
                self.auth_proto = HmacSha.SERVICE_ID
                self.use_auth_as_init = False
            elif auth_protocol == 'sha-224':
                self.authenticator = HmacSha2
                self.auth_proto = HmacSha2.SHA224_SERVICE_ID
            elif auth_protocol == 'sha-256':
                self.authenticator = HmacSha2
                self.auth_proto = HmacSha2.SHA256_SERVICE_ID
            elif auth_protocol == 'sha-384':
                self.authenticator = HmacSha2
                self.auth_proto = HmacSha2.SHA384_SERVICE_ID
            elif auth_protocol == 'sha-512':
                self.authenticator = HmacSha2
                self.auth_proto = HmacSha2.SHA512_SERVICE_ID
            else:
                raise ValueError("Improper authentication protocol or protocol not implemented")
        else:
            if auth_protocol is not None:
                raise ValueError("Auth Protocol not implemented for this security level")
            if auth_passphrase is not None:
                raise ValueError("Auth Protocol is not valid")
        
        if self.auth == 'auth-priv':
            if priv_protocol == 'aes-128':
                self.decrypter = Aes
            elif priv_protocol == 'des':
                self.decrypter = Des
            elif priv_protocol == 'des-3':
                self.decrypter = des3.Des3
            elif priv_protocol == 'aes-192':
                self.decrypter = aes192.Aes192
            elif priv_protocol == 'aes-256':
                self.decrypter = aes256.Aes256
            elif priv_protocol == 'aes-192-blue-menthal':
                self.decrypter = aes192.AesBlumenthal192
            elif priv_protocol == 'aes-256-blue-menthal':
                self.decrypter = aes256.AesBlumenthal256
            else:
                raise ValueError("Improper privacy protocol or protocol not implemented")
        else:
            if priv_protocol is not None:
                raise ValueError("Priv Protocol not implemented for this security level")
            if priv_passphrase is not None:
                raise ValueError("Priv Passphrase not valid")

        if not auth_protocol and auth_passphrase:
            raise ValueError("No Auth Protocol Defined")

        if not priv_protocol and priv_protocol:
            raise ValueError("No Priv Protocol Defined")
        

    def cbFun(self, UdpTransport, transportDomain, transportAddress, incomingMessage):

        
        trap_dict = {}
        trap_dict['address'] = transportAddress
        
        varBindList = []

        request_id, error_status, error_index, var_binds, misc = self.__messageProcessor(incomingMessage)

        trap_dict['misc'] = misc
        
        trap_dict['error_status'] = error_status
        trap_dict['error_index'] = error_index

        mib_view = view.MibViewController(self.snmp_engine.getMibBuilder())

        for oid, val in var_binds:
            oid_and_val_dict = {}
            try:
                resolved_oid = ObjectType(ObjectIdentity(oid), val).resolveWithMib(mib_view)
                oid_and_val_dict['fully_printed'] = resolved_oid.prettyPrint()
                oid_and_val_dict['symbol'] = ObjectIdentity(oid).resolveWithMib(mib_view).getMibSymbol()
                oid_and_val_dict['value'] = val
                oid_and_val_dict['oid'] = str(ObjectIdentity(oid).resolveWithMib(mib_view).getOid())
                oid_and_val_dict['status'] = 'clean'
            
            except PyAsn1Error as err:

                print(err)

                try:
                    resolved_only_oid = ObjectType(ObjectIdentity(oid)).resolveWithMib(mib_view)

                    oid_and_val_dict['fully_printed'] = "%s %s"%(resolved_oid.prettyPrint(), val)
                    oid_and_val_dict['symbol'] = ObjectIdentity(oid).resolveWithMib(mib_view).getMibSymbol()
                    oid_and_val_dict['value'] = val
                    oid_and_val_dict['oid'] = str(ObjectIdentity(oid).getOid())
                    oid_and_val_dict['status'] = 'dirty'
                
                except PyAsn1Error as err:
                    print(err)

                    oid_and_val_dict['fully_printed'] = "%s = %s"%(oid, val)
                    oid_and_val_dict['symbol'] = None
                    oid_and_val_dict['value'] = val
                    oid_and_val_dict['oid'] = oid
                    oid_and_val_dict['status'] = 'stDirty'

            finally:

                varBindList.append(oid_and_val_dict)
        trap_dict['varBindList'] = varBindList

        self.trap_in_session.append(trap_dict)

        if self.cbSec is not None:
            self.cbSec(self.trap_in_session)
    
    def __messageProcessor(self, wholeMsg):

        if self.protocol == 'v1' or self.protocol == 'v2' or self.protocol == 'v2c':
            return self.__processV1V2Message(wholeMsg)
        elif self.protocol == 'v3':
            return self.__processv3Message(wholeMsg)

    def loadMibResolver(self, mib_load_paths = [], mib_names = []):

        mib_builder = self.snmp_engine.getMibBuilder()

        mib_builder.addMibSources(*[builder.DirMibSource(each_source) for each_source in mib_load_paths])

        mib_builder.loadModules(*mib_names)

    def __processV1V2Message(self, wholeMsg):

        version = int(api.decodeMessageVersion(wholeMsg))

        pmod = api.PROTOCOL_MODULES[version]

        reqMsg, wholeMsg = decode(wholeMsg, asn1Spec=pmod.Message())

        misc = {
            'community': pmod.apiMessage.getCommunity(reqMsg)
        }

        return self.__processIncomingMessage(reqMsg, version, misc)




    def __processv3Message(self, wholeMsg):

        msg, rem = decode(wholeMsg, asn1Spec=SNMPv3Message())

        if self.auth == 'auth-no-priv':
            auth_part = True
            priv_part = False
        elif self.auth == 'auth-priv':
            auth_part = True
            priv_part = True
        elif self.auth == 'no-auth-no-priv':
            auth_part = False
            priv_part = False

        
        headerData = msg.getComponentByPosition(1)

        securityParameters = msg.getComponentByPosition(2)
           

        sec_param, rest_param = decode(securityParameters, asn1Spec=UsmSecurityParameters())
       
        authentication_parameters = sec_param['msgAuthenticationParameters']
        
        privacy_parameters = sec_param['msgPrivacyParameters']

        engine_id = sec_param['msgAuthoritativeEngineId']

        engine_boots = sec_param['msgAuthoritativeEngineBoots']

        engine_time = sec_param['msgAuthoritativeEngineTime']

        user_name = sec_param['msgUserName']

        misc = {
            'user_name': user_name,
            'auth_engine_id': engine_id,
            'engine_boots': engine_boots,
            'engine_id': engine_id
        }

        

        if auth_part:
            
            if not self.use_auth_as_init:
                hmac_class = self.authenticator()
            else:
                hmac_class = self.authenticator(self.auth_proto)

            auth_message = hmac_class.authenticateIncomingMsg(hmac_class.localizeKey(
                hmac_class.hashPassphrase(self.authPassphrase), engine_id
            ), authentication_parameters, wholeMsg)
            
            if priv_part:

                messageBody = msg.getComponentByPosition(3)['encryptedPDU'] 

                aes_prot = self.decrypter()

                priv_params = engine_boots, engine_time, privacy_parameters

                decrypted_data = aes_prot.decryptData(aes_prot.localizeKey(self.auth_proto, 
                aes_prot.hashPassphrase(self.auth_proto,self.privPassphrase),
                engine_id), priv_params, messageBody)

                data_to_decode = decrypted_data       
                decoded_data, rest = decode(data_to_decode, asn1Spec=ScopedPDU())
            
            else:
                decoded_data = msg.getComponentByPosition(3)['plaintext']

        else:
            decoded_data = msg.getComponentByPosition(3)['plaintext']

        

        return self.__processIncomingMessage(decoded_data, api.SNMP_VERSION_2C, misc)


    def __processIncomingMessage(self, messageBody, version, misc=None):
        

        pmod = api.PROTOCOL_MODULES[version]
        varPDU =  pmod.apiMessage.getPDU(messageBody)
        request_id = pmod.apiPDU.getRequestID(varPDU)
        error_status = pmod.apiPDU.getErrorStatus(varPDU)
        error_index = pmod.apiPDU.getErrorIndex(varPDU)
        var_binds = pmod.apiPDU.getVarBinds(varPDU)

        return request_id, error_status, error_index, var_binds, misc


    def registerTransports(self, server_address, server_port, timeout = None,
    cbFun = None):
        
        transporter = AsyncioDispatcher(timeout=timeout)

        transporter.registerRecvCbFun(self.cbFun)

        transporter.registerTransport(udp.snmpUDPDomain, udp.UdpTransport().openServerMode((server_address, server_port)))
        
        self.transporter = transporter

    def dispatch(self):
        self.transporter.jobStarted(1)
        self.transporter.runDispatcher()
    
    def getTrapList(self):
        return self.trap_in_session
    
    def start_listener(self, server_address, server_port, timeout):

        self.registerTransports(server_address=server_address, server_port=server_port, timeout=timeout)

        self.execution_future = self.main_loop.run_in_executor(self.thread_for_executing, self.dispatch)


    def stopDispatcher(self):
        self.transporter.jobFinished(1)
        self.transporter.closeDispatcher()
   
    def stop_listener(self):

        self.stopDispatcher()

        self.execution_future.cancel()

        while(not self.execution_future.cancelled()):
            time.sleep(1)

        self.main_loop.stop()
        self.thread_for_executing.shutdown()

