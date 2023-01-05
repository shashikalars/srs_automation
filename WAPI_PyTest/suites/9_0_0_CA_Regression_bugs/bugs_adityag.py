import re
import sys
import config
import pytest
import unittest
import logging
import json
import subprocess
from time import sleep
import ib_utils.ib_NIOS as ib_NIOS
from time import sleep
import pexpect
import paramiko
from ib_utils.start_stop_logs import log_action as log
from ib_utils.file_content_validation import log_validation as logv
import ib_utils.common_utilities as common_util

logging.basicConfig(filename='nios-9-0.log', filemode='w', level=logging.DEBUG)

def display_msg(msg):
    print(msg)
    logging.info(msg)

def dns_restart_services():
    print("\n============================================\n")
    print("DNS Restart Services")
    print("\n============================================\n")

    grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
    ref = json.loads(grid)[0]['_ref']
    data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
    request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
    sleep(10)




class BUG_AUTO_9_0(unittest.TestCase):

    @pytest.mark.run(order=56)
    def test_056_Create_an_auth_zone(self):
        display_msg("Create auth zone")

        data = {"fqdn":"infoblox.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Create authoratative zone.")
            assert False
        else:
            display_msg("\n--------------------------------------------------------\n")
            display_msg("Validating Authoratative zone - infoblox.com")
            display_msg("\n--------------------------------------------------------\n")

            response = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=infoblox.com", grid_vip=config.grid_vip)
            response=json.loads(response)[0]
            display_msg(response)

            if 'infoblox.com' in response['_ref']:
                display_msg(response["_ref"])
                display_msg("SUCCESS: Authoratative Zone 'infoblox.com' was created!")
                dns_restart_services()
                assert True
            else:
                display_msg("FAILURE: Authoratative Zone 'infoblox.com' creation failed")
                assert False

    
    @pytest.mark.run(order=57)
    def test_057_Add_A_record_to_the_auth_zone(self):
        display_msg("Add A record to the auth zone")

        data = {"ipv4addr": "1.2.3.4",
            "name": "a.infoblox.com",
            "view": "default"}
        response = ib_NIOS.wapi_request('POST', object_type="record:a", fields=json.dumps(data))
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:
    
            assert False
        else:

            assert True


    @pytest.mark.run(order=58)
    def test_058_NIOS_84672_Perform_dig_query_on_the_A_record_from_the_grid(self):
        display_msg("Perform dig query on the A records from the grid")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("dig @"+config.grid_vip+" a.infoblox.com IN A")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('1.2.3.4' in output):
            display_msg("Dig query successfull")
            assert True
        else:
            display_msg("Dig query failed")
            assert False

    @pytest.mark.run(order=59)
    def test_059_NIOS_84672_Validate_if_core_files_were_generated_after_dig_operation(self):
        display_msg("Validate if cores were generated after the dig operation")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("ls -ltr /storage/cores")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('core.dig' in output):
            display_msg("Core files have been generated")
            assert False
        else:
            display_msg("Core file have not been generated")
            assert True

    @pytest.mark.run(order=60)
    def test_060_NIOS_84694_81654_Perform_nsupdate_from_the_grid(self):
        display_msg("Perform nspdate from the grid")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("nsupdate")
        child.expect(">")
        child.sendline("quit")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('error' in output):
            display_msg("ns update unsuccessfull")
            assert False
        else:
            display_msg("ns update successfull")
            assert True

    @pytest.mark.run(order=61)
    def test_061_NIOS_84694_81654_Validate_if_core_files_were_generated_after_nsupdate_operation(self):
        display_msg("Validate if cores were generated after the nsupdate operation")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("ls -ltr /storage/cores")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('core.nsupdate' in output):
            display_msg("Core files have been generated")
            assert False
        else:
            display_msg("Core file have not been generated")
            assert True

    @pytest.mark.run(order=62)
    def test_062_NIOS_83213_Add_ALIAS_Record_of_type_A_record(self):
        display_msg("Add ALIAS record of type A record")
        data = {"name": "alias.infoblox.com","target_name": "a.infoblox.com","target_type": "A","view": "default"}
        response = ib_NIOS.wapi_request('POST', object_type = "record:alias",fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("ALIAS record creation failed")
            assert False
        else:
            display_msg("ALIAS record creation successfull")
            assert True

    @pytest.mark.run(order=63)
    def test_063_NIOS_83213_Perform_dig_operation_on_the_ALIAS_record(self):
        display_msg("Perform dig operation on the ALIAS record")
        try:
            output = subprocess.check_output(['dig','@'+config.grid_vip,'alias.infoblox.com','IN','A'])
        except subprocess.CalledProcessError as e:
            display_msg("Error encountered while executing dig query")
            display_msg(e)
            assert False
        else:
            display_msg(output)
            if '1.2.3.4' in output:
                display_msg("Dig operation successfull")
                assert True
            else:
                display_msg("Dig operation was unsuccessfull")
                assert False

    @pytest.mark.run(order=64)
    def test_064_NIOS_83213_Validate_if_core_files_were_generated_after_dig_operation(self):
        display_msg("Validate if cores were generated after the dig operation")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("ls -ltr /storage/cores")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('core.isc-net-0000' in output):
            display_msg("Core files have been generated")
            assert False
        else:
            display_msg("Core file have not been generated")
            assert True


    @pytest.mark.run(order=65)
    def test_065_NIOS_82043_Set_return_minimal_responses_to_false_on_member_dns(self):
        display_msg("Set 'return minimal responses' to False in member DNS properties")
        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns", grid_vip=config.grid_vip)
        display_msg(get_ref)
        for ref in json.loads(get_ref):
            if ref["ipv4addr"] == config.grid_vip:
                member_dns_ref = ref['_ref']
                break
        data = {"minimal_resp":False}
        response = ib_NIOS.wapi_request('PUT', object_type=member_dns_ref,fields=json.dumps(data))
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("Unable to set 'Return minimal response' to False")
            assert False
        else:
            display_msg("'Return minimal response' set to False")
            dns_restart_services()
            assert True

    @pytest.mark.run(order=66)
    def test_066_NIOS_82043_Perform_dig_query_and_check_if_additional_sections_are_returned_in_the_response(self):
        display_msg("Perform dig query and check if additional sections are returned in the response")
        try:
            output = subprocess.check_output(['dig','@'+config.grid_vip,'a.infoblox.com','IN','A'])
        except subprocess.CalledProcessError as e:
            display_msg("Error encountered while executing dig query")
            display_msg(e)
            assert False
        else:
            display_msg(output)
            count = 0
            if ';; AUTHORITY SECTION:' in output:
                count +=1 
                display_msg("Authority section present under the response")
            
            if ';; ADDITIONAL SECTION:' in output:
                count +=1
                display_msg("Additional section present under the response")

            if count == 2:
                display_msg("The dig repsonse did not return minimal response as expected")
                assert True
            else:
                display_msg("The dig response returned minimal response, when the 'Return minimal response' has been set to False")
                assert False

        
    @pytest.mark.run(order=67)
    def test_067_NIOS_82043_Set_return_minimal_responses_to_true_on_member_dns(self):
        display_msg("Set 'return minimal responses' to True in member DNS properties")
        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns", grid_vip=config.grid_vip)
        display_msg(get_ref)
        for ref in json.loads(get_ref):
            if ref["ipv4addr"] == config.grid_vip:
                member_dns_ref = ref['_ref']
                break
        data = {"minimal_resp":True}
        response = ib_NIOS.wapi_request('PUT', object_type=member_dns_ref,fields=json.dumps(data))
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("Unable to set 'Return minimal response' to True")
            assert False
        else:
            display_msg("'Return minimal response' set to True")
            dns_restart_services()
            assert True


    @pytest.mark.run(order=68)
    def test_068_NIOS_87882_Create_EA_zone_Ipv4Nw_EAInheritance_Enabled(self):
        display_msg("Create EA attribute with zone and ipv4 nw with EA_Inheritance enabled")
        data = {"name": "st1", "type": "STRING","max": 10,"min": 1,"flags": "I","allowed_object_types": [ "BaseZone","Network"]}
        post_ref = ib_NIOS.wapi_request('POST', object_type="extensibleattributedef",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(post_ref)
        if type(post_ref)== tuple:
            display_msg("Creating EA attribute failed")
            assert False
        else:
            display_msg("Creation of EA Attribute success")
            assert True


    @pytest.mark.run(order=69)
    def test_069_NIOS_87882_Create_Auth_zone_with_EA_Attribute_Enabled(self):
        display_msg("Create auth_zone with EA  Attribute enabled")
        data={"extattrs": {"st1": {"value": "15"}},"fqdn": "test2.com","grid_primary": [{"name": "ib-10-35-155-18.infoblox.com"}]}
        post_ref = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(post_ref)
        if type(post_ref)== tuple:
            display_msg("Creating auth_zone  with EA Attribute enabled failed")
            assert False
        else:
            display_msg("Creating auth_zone  with EA Attribute enabled success")
            assert True
    
    @pytest.mark.run(order=70)
    def test_070_test_NIOS_82456_Create_authzone_Unknown_record_type_TYPE65535_withSubfields(self):
       # display_msg("Create Unknwon record TYPE65535 with subfields")
       # data= {"name": "p3.com"}
        display_msg("Create auth zone")

        data = {"fqdn":"p3.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if type(response)== tuple:
            display_msg("Creating auth_zone Failed")
            assert False
        else:
            display_msg("Creating auth_zone  Success")
            dns_restart_services()
            assert True
    @pytest.mark.run(order=71)
    def test_071_test_NIOS_82456_Create_authzone_Unknown_record_type_TYPE65535_withSubfields(self):
        display_msg("Create Unknwon record TYPE65535 with subfields")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        data={"name": "uk1.p3.com","record_type": "TYPE65535","subfield_values": [ {"field_type": "H","field_value": "1100","include_length": "8_BIT"},{"field_type": "X","field_value": "abcd","include_length":"8_BIT"},{"field_type": "S","field_value": "12","include_length": "NONE"},{"field_type": "I","field_value": "12","include_length": "NONE"},{"field_type": "6","field_value": "1234::1","include_length": "NONE"}]}
        response=ib_NIOS.wapi_request('POST', object_type="record:unknown", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if type(response)== tuple:
            display_msg("Creating Unknown record with TYPE65535  Failed")
            assert False
        else:
            display_msg("Creating Unknown record with TYPE65535  Success")
            assert True

    @pytest.mark.run(order=72)
    def test_072_test_NIOS_82456_Validate_Infoblox_log_for_errors(self):
        display_msg("Validate Infoblox.log for errors ")
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log1=logv(".*Required Value(s) Missing: record_rdata_hash.*","/infoblox/var/infoblox.log",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True 
    

    @pytest.mark.run(order=73)
    def test_073_test_NIOS_84643_enable_dns(self):
          logging.info("starting DNS service")
          get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns", grid_vip=config.grid_vip)
          logging.info(get_ref)
          res = json.loads(get_ref)
          ref1 = json.loads(get_ref)[0]['_ref']
          print (ref1)
          data = {"enable_dns": True}
          response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data), grid_vip=config.grid_vip)
          sleep(5)
          logging.info(response)
          print (response)
          print("Successfully started DNS service")
    
    @pytest.mark.run(order=74)
    def test_074_test_NIOS_84643_Create_Auth_zone(self):
        display_msg("Create auth zone with member assignment")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:

            assert True

    

    @pytest.mark.run(order=75)
    def test_075_NIOS_84643_Validate_Zone_Signing(self):
        display_msg("Validate Zone Signing")
        get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
        res=json.loads(get_ref)
        display_msg(res)
        sleep(5)
        for zone  in res:
            if  zone['fqdn']=='test.com':
                zone_auth_ref=zone['_ref']
        signzone_ref = ib_NIOS.wapi_request('POST', ref=str(zone_auth_ref), params='?_function=dnssec_operation', fields=json.dumps({"operation":"SIGN"}))
        logging.info(signzone_ref)
        if bool(re.match("{}",str(signzone_ref))):
            logging.info("Zone signed successfully")
            dns_restart_services()
        else:
            raise Exception("Zone signing unsuccessfull")

    
    @pytest.mark.run(order=76)
    def test_076_NIOS_84643_Validate_if_core_files_were_generated_after_zone_signing_operation(self):
        display_msg("Validate if cores were generated after the dig operation")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("ls -ltr /storage/cores")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('core.dnssec-signzone.SIGABRT' in output):
            display_msg("Core files have been generated")
            assert False
        else:
            display_msg("Core file have not been generated")
            assert True

    @pytest.mark.run(order=77)
    def test_077_test_NIOS_84008_enable_dns(self):
          logging.info("starting DNS service")
          get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns", grid_vip=config.grid_vip)
          logging.info(get_ref)
          res = json.loads(get_ref)
          ref1 = json.loads(get_ref)[0]['_ref']
          print (ref1)
          data = {"enable_dns": True}
          response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data), grid_vip=config.grid_vip)
          sleep(5)
          logging.info(response)
          print (response)
          print("Successfully started DNS service")


    @pytest.mark.run(order=78)
    def test_078_test_NIOS_84008_Create_Auth_zone(self):
        display_msg("Create auth zone with member assignment")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:

            assert True


    @pytest.mark.run(order=79)
    def test_079_NIOS_84008_Validate_Zone_Signing(self):
        display_msg("Validate Zone Signing")
        log("start","/var/log/syslog",config.grid_vip)
        get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
        res=json.loads(get_ref)
        display_msg(res)
        sleep(5)
        for zone  in res:
            if  zone['fqdn']=='test.com':
                zone_auth_ref=zone['_ref']
        signzone_ref = ib_NIOS.wapi_request('POST', ref=str(zone_auth_ref), params='?_function=dnssec_operation', fields=json.dumps({"operation":"SIGN"}))
        logging.info(signzone_ref)
        if bool(re.match("{}",str(signzone_ref))):
            logging.info("Zone signed successfully")
            dns_restart_services()
        else:
            raise Exception("Zone signing unsuccessfull")



    @pytest.mark.run(order=80)
    def test_080_test_NIOS_84008_Validate_sys_log_for_errors(self):
        display_msg("Validate var/log/syslog for errors ")
        log("stop","/var/log/syslog",config.grid_vip)
        log1=logv("malformed transaction: serial number did not increase apply_txn_zrq_items:dns_journal_write_transaction -> unexpected error ","/var/log/syslog",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True


    @pytest.mark.run(order=81)
    def test_081_test_NIOS_84008_enable_dns(self):
          logging.info("starting DNS service")
          get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns", grid_vip=config.grid_vip)
          logging.info(get_ref)
          res = json.loads(get_ref)
          ref1 = json.loads(get_ref)[0]['_ref']
          print (ref1)
          data = {"enable_dns": True}
          response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data), grid_vip=config.grid_vip)
          sleep(5)
          logging.info(response)
          print (response)
          print("Successfully started DNS service")


    @pytest.mark.run(order=82)
    def test_082_test_NIOS_84008_Create_Auth_zone_with_Member_asGrid_Primary(self):
        display_msg("Create auth zone with member as Grid Primary")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_member_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:

            assert True


    @pytest.mark.run(order=83)
    def test_083_NIOS_84008_Validate_Zone_Signing_With_Member_asGridPrimary(self):
        display_msg("Validate Zone Signing with Member as Grid Primary")
        get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
        res=json.loads(get_ref)
        display_msg(res)
        sleep(5)
        for zone  in res:
            if  zone['fqdn']=='test.com':
                zone_auth_ref=zone['_ref']
        signzone_ref = ib_NIOS.wapi_request('POST', ref=str(zone_auth_ref), params='?_function=dnssec_operation', fields=json.dumps({"operation":"SIGN"}))
        logging.info(signzone_ref)
        if bool(re.match("{}",str(signzone_ref))):
            logging.info("Zone signed successfully")
            dns_restart_services()
        else:
            raise Exception("Zone signing unsuccessfull")

    @pytest.mark.run(order=84)
    def test_084_test_NIOS_84008_enable_dns(self):
          logging.info("starting DNS service")
          get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns", grid_vip=config.grid_vip)
          logging.info(get_ref)
          res = json.loads(get_ref)
          ref1 = json.loads(get_ref)[0]['_ref']
          print (ref1)
          data = {"enable_dns": True}
          response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data), grid_vip=config.grid_vip)
          sleep(5)
          logging.info(response)
          print (response)
          print("Successfully started DNS service")


    @pytest.mark.run(order=85)
    def test_085_test_NIOS_84008_Create_Auth_zone_with_Master_asGrid_Primary_and_Member_asGridSecondary(self):
        display_msg("Create auth zone with master as Grid Primary and Member as grid secondary")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_fqdn}],"grid_secondaries":[{"name":config.grid_member_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:

            assert True

    @pytest.mark.run(order=86)
    def test_086_NIOS_84008_Validate_Zone_Signing_With_Master_asGridPrimary_and_Member_as_Grid_Secondary(self):
        display_msg("Validate Zone Signing with Master as Grid Primary and Member as Grid Secondary")
        get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
        res=json.loads(get_ref)
        display_msg(res)
        sleep(5)
        for zone  in res:
            if  zone['fqdn']=='test.com':
                zone_auth_ref=zone['_ref']
        signzone_ref = ib_NIOS.wapi_request('POST', ref=str(zone_auth_ref), params='?_function=dnssec_operation', fields=json.dumps({"operation":"SIGN"}))
        logging.info(signzone_ref)
        if bool(re.match("{}",str(signzone_ref))):
            logging.info("Zone signed successfully")
            dns_restart_services()
        else:
            raise Exception("Zone signing unsuccessfull")


    @pytest.mark.run(order=87)
    def test_087_test_NIOS_83040_enable_dns(self):
          logging.info("starting DNS service")
          get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns", grid_vip=config.grid_vip)
          logging.info(get_ref)
          res = json.loads(get_ref)
          for ref in res:
             if config.grid_fqdn==ref['host_name']:
                    ref1 = json.loads(get_ref)[0]['_ref']
                    data = {"enable_dns": True}
                    response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data), grid_vip=config.grid_vip)
                    sleep(5)
                    logging.info(response)
                    print (response)
                    print("Successfully started DNS service")
             elif config.grid_member_fqdn==ref['host_name']:
                    ref2 = json.loads(get_ref)[1]['_ref']
                    print (ref2)
                    data = {"enable_dns": True}
                    response = ib_NIOS.wapi_request('PUT',ref=ref2,fields=json.dumps(data), grid_vip=config.grid_vip)
                    sleep(5)
                    logging.info(response)
                    print (response)
                    print("Successfully started DNS service")


    @pytest.mark.run(order=88)
    def test_088_test_NIOS_83040_Create_Auth_zone_with_Member_asGrid_Primary_and_Master_asGridSecondary(self):
        display_msg("Create auth zone with member as Grid Primary and Master as Grid Secondary")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_member_fqdn}],"grid_secondaries":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:
            assert True


    @pytest.mark.run(order=89)
    def test_089_NIOS_NIOS_83040_Validate_Zone_Signing_With_Member_asGridPrimary_and_GridMasterr_as_Grid_Secondary(self):
        display_msg("Validate Zone Signing with Member as Grid Primary and Master as Grid Secondary")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
        res=json.loads(get_ref)
        display_msg(res)
        sleep(5)
        for zone  in res:
            if  zone['fqdn']=='test.com':
                zone_auth_ref=zone['_ref']
        signzone_ref = ib_NIOS.wapi_request('POST', ref=str(zone_auth_ref), params='?_function=dnssec_operation', fields=json.dumps({"operation":"SIGN"}))
        logging.info(signzone_ref)
        if bool(re.match("{}",str(signzone_ref))):
            logging.info("Zone signed successfully")
            dns_restart_services()
        else:
            raise Exception("Zone signing unsuccessfull")


    @pytest.mark.run(order=90)
    def test_090_test_NIOS_83040_Validate_Infoblox_log_for_errors(self):
        display_msg("Validate Infoblox.log for errors ")
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log1=logv("TypeError: ord() expected string of length 1, but int found","/infoblox/var/infoblox.log",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True


    @pytest.mark.run(order=91)
    def test_091_test_NIOS_82452_Create_authzone_Unknown_record_type_NULL_withSubfields(self):
        display_msg("Create auth zone")

        data = {"fqdn":"p3.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if type(response)== tuple:
            display_msg("Creating auth_zone Failed")
            assert False
        else:
            display_msg("Creating auth_zone  Success")
            dns_restart_services()
            assert True



    @pytest.mark.run(order=92)
    def test_092_test_NIOS_82452_Create_authzone_Unknown_record_type_NULL_withSubfields(self):
       # display_msg("Create Unknwon record TYPE65535 with subfields")
       # data= {"name": "p3.com"}
        display_msg("Create auth zone")

        data = {"fqdn":"p3.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if type(response)== tuple:
            display_msg("Creating auth_zone Failed")
            assert False
        else:
            display_msg("Creating auth_zone  Success")
            dns_restart_services()
            assert True



    @pytest.mark.run(order=93)
    def test_093_test_NIOS_82452_Create_authzone_Unknown_record_type_TYPE65535_withSubfields(self):
        display_msg("Create Unknwon record TYPENULL with subfields")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        data={"name": "uk1.p3.com","record_type": "NULL","subfield_values":[{"field_type": "H","field_value": "1100","include_length": "8_BIT"},{"field_type": "X","field_value": "abcd","include_length": "8_BIT"},{"field_type": "S","field_value": "12","include_length": "NONE"},{"field_type": "I","field_value":"234","include_length": "NONE"},{"field_type": "4","field_value": "1.2.3.4","include_length": "NONE"},{"field_type": "B","field_value": "1","include_length": "NONE"},{"field_type": "N","field_value": "a.com","include_length": "NONE"},{"field_type": "T","field_value": "sss","include_length": "8_BIT"},{"field_type": "6","field_value": "1234::1","include_length": "NONE"}]}
        response=ib_NIOS.wapi_request('POST', object_type="record:unknown", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if type(response)== tuple:
            display_msg("Creating Unknown record with TYPENULL  Failed")
            assert False
        else:
            display_msg("Creating Unknown record with TYPENULL  Success")
            assert True




    @pytest.mark.run(order=94)
    def test_094_test_NIOS_82452_Validate_Infoblox_log_for_errors(self):
        display_msg("Validate Infoblox.log for errors ")
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log1=logv(".*Required Value(s) Missing: record_rdata_hash.*","/infoblox/var/infoblox.log",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True



    @pytest.mark.run(order=95)
    def test_095_test_NIOS_82227_enable_dns(self):
          logging.info("starting DNS service")
          get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns", grid_vip=config.grid_vip)
          logging.info(get_ref)
          res = json.loads(get_ref)
          ref1 = json.loads(get_ref)[0]['_ref']
          print (ref1)
          data = {"enable_dns": True}
          response = ib_NIOS.wapi_request('PUT',ref=ref1,fields=json.dumps(data), grid_vip=config.grid_vip)
          sleep(5)
          logging.info(response)
          print (response)
          print("Successfully started DNS service")


    @pytest.mark.run(order=96)
    def test_096_test_NIOS_82227_Create_Auth_zone(self):
        display_msg("Create auth zone with member assignment")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:

            assert True

    @pytest.mark.run(order=97)
    def test_097_NIOS_82227_ZoneSigning(self):
        display_msg("Validate Zone Signing")
        get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
        res=json.loads(get_ref)
        display_msg(res)
        sleep(5)
        for zone  in res:
            if  zone['fqdn']=='test.com':
                zone_auth_ref=zone['_ref']
        signzone_ref = ib_NIOS.wapi_request('POST', ref=str(zone_auth_ref), params='?_function=dnssec_operation', fields=json.dumps({"operation":"SIGN"}))
        logging.info(signzone_ref)
        if bool(re.match("{}",str(signzone_ref))):
            logging.info("Zone Signing is  success")
            dns_restart_services()
        else:
            raise Exception("Zone Signing  is  unsuccessful")


    @pytest.mark.run(order=98)
    def test_098_NIOS_82227_ROLLOVER_ZSK_(self):
                logging.info("ROLLOVER_ZSK for the signed zone")
                data = {"fqdn":"test.com"}
                endpoint=common_util.get_object_reference(object_type="zone_auth",data=data)
                ref=endpoint
                print ("###########",ref)
                data={"operation":"ROLLOVER_ZSK"}
                response = ib_NIOS.wapi_request('POST', object_type=ref,fields=json.dumps(data),params="?_function=dnssec_operation")
                print (response)
                for read in response:
                        assert True
                print("Rollover ZSK for signed zone is completed`")
                dns_restart_services()



    
    @pytest.mark.run(order=99)
    def test_099_NIOS_82227_ZoneSigning(self):
        display_msg("Validate Zone Signing")
        get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
        res=json.loads(get_ref)
        display_msg(res)
        sleep(5)
        for zone  in res:
            if  zone['fqdn']=='test.com':
                zone_auth_ref=zone['_ref']
        signzone_ref = ib_NIOS.wapi_request('POST', ref=str(zone_auth_ref), params='?_function=dnssec_operation', fields=json.dumps({"operation":"SIGN"}))
        logging.info(signzone_ref)
        if bool(re.match("{}",str(signzone_ref))):
            logging.info("Zone Signing is  success")
            dns_restart_services()
        else:
            raise Exception("Zone Signing  is  unsuccessful")



    @pytest.mark.run(order=100)
    def test_100_NIOS_81826_Change_grid_dns(self):
                logging.info("Change grid:dns properties  Allow Updates to allow any")
                get_ref = ib_NIOS.wapi_request('GET', object_type="grid:dns", grid_vip=config.grid_vip)
                res=json.loads(get_ref)
                print ("###########",res[0]['_ref'])
                data={"allow_update": [{"_struct": "addressac","address": "Any","permission": "ALLOW"}]}
                response = ib_NIOS.wapi_request('PUT', object_type=res[0]['_ref'],fields=json.dumps(data))
                print(response)
                for read in response:
                        assert True
                print("Grid:DNS Properties Allow updates is set to Allow Any")
                dns_restart_services()


    @pytest.mark.run(order=101)
    def test_101_test_NIOS_81826__Create_authzone(self):
        display_msg("Create auth zone")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if type(response)== tuple:
            display_msg("Creating auth_zone Failed")
            assert False
        else:
            display_msg("Creating auth_zone  Success")
            dns_restart_services()

    @pytest.mark.run(order=102)
    def test_102_NIOS_81826_Create_NSUpdate_RR_Record(self):
        log("start","/var/log/syslog",config.grid_vip)
        display_msg("Create  RR Record through ns update")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("nsupdate")
        child.sendline("server "+config.grid_vip)
        child.sendline("update add ajith.test.com 111 A 5.5.5.5")
        child.sendline("send")
        child.sendline("quit")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('-' in output):
            display_msg("Record creation is success through nsupdate")
            assert True
        else:
            display_msg("Record creation is failed through nsupdate")
            assert False


    @pytest.mark.run(order=103)
    def test_103_NIOS_81826_Validate_sys_log_for_errors(self):
        display_msg("Validate var/log/syslog for errors ")
        log("stop","/var/log/syslog",config.grid_vip)
        log1=logv("ajith.test.com IN SOA - "+config.grid_vip + "ajith.test.com IN SOA response: NXDOMAIN +A","/var/log/syslog",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True



    @pytest.mark.run(order=104)
    def test_104_test_NIOS_81823_Create_Auth_zone_Import_Records_from_grid2_to_grid1_enable_Zone_Transfer(self):
        display_msg("Create auth zone with member assignment")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:

            assert True


    @pytest.mark.run(order=105)
    def test_105_NIOS_81823_Import_Records_from_grid2_to_grid1_enable_Zone_Transfer(self):
                logging.info("Change grid:dns properties  Zone Transfer to allow any")
                get_ref = ib_NIOS.wapi_request('GET', object_type="grid:dns", grid_vip=config.grid_vip)
                res=json.loads(get_ref)
                print ("###########",res[0]['_ref'])
                data={"allow_transfer": [{"_struct": "addressac","address": "Any","permission": "ALLOW"}]}
                response = ib_NIOS.wapi_request('PUT', object_type=res[0]['_ref'],fields=json.dumps(data))
                print(response)
                for read in response:
                        assert True
                print("Grid:DNS Properties Allow transfer is set to Allow Any")
                dns_restart_services()


    @pytest.mark.run(order=106)
    def test_106_NIOS_81823_ImportRecords_From_grid2_to_grid1(self):
                log("start","/var/log/syslog",config.grid_vip)
                logging.info("Copying records from grid2 to grid1")
                data={"import_from": config.grid_vip2}
                get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
                response=json.loads(get_ref)
                for res in response:
                    if res['fqdn']=="test.com":
                        ref_zone=res['_ref']
                res=json.loads(get_ref)
                print ("###########",ref_zone)
                response2 = ib_NIOS.wapi_request('PUT', object_type=ref_zone,fields=json.dumps(data))
                print(response2)
                for read in response:
                        assert True
                print("Import Grid Records success from grid2 to grid1")
                dns_restart_services()


    @pytest.mark.run(order=107)
    def test_107_NIOS_81823_Validate_sys_log_for_errors(self):
        display_msg("Validate var/log/syslog for errors ")
        log("stop","/var/log/syslog",config.grid_vip)
        log1=logv("ssindex.c:9274 __xxx_get_any_rr_by_zone_and_name_internal(): not found ssindex.c:9413 __xxx_get_any_rr_by_zone_and_display_name(): not found","/var/log/syslog",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True



    @pytest.mark.run(order=108)
    def test_108_test_NIOS_81656_Create_Auth_zone_Import_Records_from_grid2_to_grid1_enable_Zone_Transfer(self):
        display_msg("Create auth zone with member assignment")

        data = {"fqdn":"test.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:

            assert True

    
    @pytest.mark.run(order=109)
    def test_109_NIOS_81656_Import_Records_from_grid2_to_grid1_enable_Zone_Transfer(self):
                logging.info("Change grid:dns properties  Zone Transfer to allow any")
                get_ref = ib_NIOS.wapi_request('GET', object_type="grid:dns", grid_vip=config.grid_vip)
                res=json.loads(get_ref)
                print ("###########",res[0]['_ref'])
                data={"allow_transfer": [{"_struct": "addressac","address": "Any","permission": "ALLOW"}]}
                response = ib_NIOS.wapi_request('PUT', object_type=res[0]['_ref'],fields=json.dumps(data))
                print(response)
                for read in response:
                        assert True
                print("Grid:DNS Properties Allow transfer is set to Allow Any")
                dns_restart_services()
    
    @pytest.mark.run(order=110)
    def test_110_NIOS_81656_ImportRecords_From_grid2_to_grid1(self):
                log("start","/infoblox/var/infoblox.log",config.grid_vip)
                logging.info("Copying records from grid2 to grid1")
                data={"import_from": config.grid_vip2}
                get_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth", grid_vip=config.grid_vip)
                response=json.loads(get_ref)
                for res in response:
                    if res['fqdn']=="test.com":
                        ref_zone=res['_ref']
                res=json.loads(get_ref)
                print ("###########",ref_zone)
                response2 = ib_NIOS.wapi_request('PUT', object_type=ref_zone,fields=json.dumps(data))
                print(response2)
                for read in response:
                        assert True
                print("Import Grid Records success from grid2 to grid1")
                dns_restart_services()

    
    @pytest.mark.run(order=111)
    def test_111_NIOS_81656_Validate_sys_log_for_errors(self):
        display_msg("Validate /infoblox/var/infoblox.log  for errors ")
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log1=logv("core.isc-worker0001.SIGABRT.395014","/infoblox/var/infoblox.log",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True


    @pytest.mark.run(order=112)
    def test_112_Enable_recursion_Queries_and_start_DNS_service(self):

        display_msg("**********************************************")
        display_msg("*              Testcase 02                   *")
        display_msg("**********************************************")
        display_msg("-------Start DNS service-------")

        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns")
        display_msg("Member DNS reference")
        display_msg(get_ref)
        member_dns_ref = json.loads(get_ref)[0]['_ref']
        data = {"enable_dns": True}
        response = ib_NIOS.wapi_request('PUT', ref=member_dns_ref, fields=json.dumps(data))
        display_msg("Enable DNS, request response")
        if bool(re.match("\"member:dns*.",str(response))):
            display_msg("DNS service started successfully")
            sleep(20)
            assert True
        else:
            display_msg("Starting DNS service failed")
            assert False
        display_msg("-------Enabling recursion and queries on Grid DNS-------")

        display_msg("Fetch Grid DNS reference")
        get_grid_dns_ref = ib_NIOS.wapi_request('GET', object_type='grid:dns')
        display_msg("Grid DNS reference is given below")
        display_msg(get_grid_dns_ref)
        grid_dns_ref = json.loads(get_grid_dns_ref)[0]['_ref']
        data = {"allow_recursive_query": True,"logging_categories":{"log_queries": True}}
        response = ib_NIOS.wapi_request('PUT', ref=grid_dns_ref, fields=json.dumps(data))
        display_msg("Response for enable recursion on Grid DNS")
        display_msg(response)
        if bool(re.match("\"grid:dns*.",str(response))):
            display_msg("Recursion enabled and queries enabled successfully")
            dns_restart_services()
            assert True
        else:
            display_msg("Enabling recursion on the grid failed")
            assert False


    @pytest.mark.run(order=113)
    def test_113_NIOS_81257_add_fwd_zone_with_forwarder(self):
          print("Creating fwd zone")
          log("start","/var/log/syslog",config.grid_vip)
          forward_zone={"fqdn":"fwd1.com","forward_to":[{"address":config.grid_vip2,"name":config.grid_fqdn2}]}
          response = ib_NIOS.wapi_request('POST', object_type="zone_forward", fields=json.dumps(forward_zone))
          print(response)
          if response[0]==400 or response[0]==401 or response[0]==402:
           assert False
           dns_restart_services()
          else:

            assert True
          print ("Added Forward Zones as expected")
          zones=ib_NIOS.wapi_request('GET', object_type="zone_forward")
          print (zones)


    @pytest.mark.run(order=114)
    def test_114_NIOS_81257_Validate_sys_log_for_errors(self):
        display_msg("Validate var/log/syslog for errors ")
        log("stop","/var/log/syslog",config.grid_vip)
        log1=logv("exceeded max queries resolving","/var/log/syslog",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True


    @pytest.mark.run(order=115)
    def test_115_test_NIOS_81255_Create_authzone(self):
        display_msg("Create auth zone")

        data = {"fqdn":"p4.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if type(response)== tuple:
            display_msg("Creating auth_zone Failed")
            assert False
        else:
            display_msg("Creating auth_zone  Success")
            dns_restart_services()
            assert True

    

    @pytest.mark.run(order=116)
    def test_116_NIOS_81255_Perform_dig_query_and_check_if_Recursion_Cache_View_Recursion_Client_Quota_exists(self):
        log("start","/var/log/syslog",config.grid_vip)
        display_msg("Perform dig query on the p4.com from the grid")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("dig @"+config.grid_vip+" p4.com")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('p4.com' in output):
            display_msg("Dig query successfull")
            assert True
        else:
            display_msg("Dig query failed")
            assert False


    @pytest.mark.run(order=117)
    def test_117_NIOS_81255_Validate_sys_log_for_errors(self):
        sleep(300)
        display_msg("Validate var/log/syslog for errors ")
        log("stop","/var/log/syslog",config.grid_vip)
        log1=logv("Recursion cache view Recursion client quota:","/var/log/syslog",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True


    @pytest.mark.run(order=118)
    def test_118_81254_Enable_recursion_Queries_Response_filter_aaaa_and_start_DNS_service(self):

        display_msg("-------Start DNS service-------")

        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns")
        display_msg("Member DNS reference")
        display_msg(get_ref)
        member_dns_ref = json.loads(get_ref)[0]['_ref']
        data = {"enable_dns": True}
        response = ib_NIOS.wapi_request('PUT', ref=member_dns_ref, fields=json.dumps(data))
        display_msg("Enable DNS, request response")
        if bool(re.match("\"member:dns*.",str(response))):
            display_msg("DNS service started successfully")
            sleep(20)
            assert True
        else:
            display_msg("Starting DNS service failed")
            assert False
        display_msg("-------Enabling recursion,queries responses and filter_aaaa on grid:dns------")

        display_msg("Fetch Grid DNS reference")
        get_grid_dns_ref = ib_NIOS.wapi_request('GET', object_type='grid:dns')
        display_msg("Grid DNS reference is given below")
        display_msg(get_grid_dns_ref)
        grid_dns_ref = json.loads(get_grid_dns_ref)[0]['_ref']
        data = {"allow_recursive_query": True,"logging_categories":{"log_queries": True,'log_responses': True} ,"filter_aaaa": "YES","forwarders":[config.grid_vip2]}
        response = ib_NIOS.wapi_request('PUT', ref=grid_dns_ref, fields=json.dumps(data))
        display_msg("Response for enable recursion  ,queries,responses and filter_aaaa on Grid DNS")
        display_msg(response)
        if bool(re.match("\"grid:dns*.",str(response))):
            display_msg("Recursion,queries,responses and filter_aaaa enabled  and forwarder added successfully")
            dns_restart_services()
            assert True
        else:
            display_msg("ecursion,queries,responses and filter_aaaa not enabled  and forwarder failed")
            assert False



    @pytest.mark.run(order=119)
    def test_119_test_NIOS_81254_Create_Auth_zone(self):
        display_msg("Create auth zone with member assignment")

        data = {"fqdn":"b1.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:
            assert True
            dns_restart_services()


    @pytest.mark.run(order=120)
    def test_120_NIOS_81254_Perform_dig_query_on_the_grid(self):
        log("start","/var/log/syslog",config.grid_vip)
        display_msg("Perform dig query to test AAAA filtering ")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no root@'+config.grid_vip,timeout=300)
        child.expect("bash-5.0#")
        child.sendline("dig @"+config.grid_vip+" b1.com aaaa")
        child.expect("bash-5.0#")
        output = child.before
        print(output)
        child.close()
        if('b1.com' in output):
            display_msg("Dig query successfull")
            assert True
        else:
            display_msg("Dig query failed")
            assert False


    @pytest.mark.run(order=121)
    def test_121_NIOS_81254_Validate_sys_log_for_errors(self):
        display_msg("Validate var/log/syslog for errors ")
        log("stop","/var/log/syslog",config.grid_vip)
        log1=logv("b1.com IN AAAA","/var/log/syslog",config.grid_vip)
        if log1 :
            display_msg("Error logs found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True


    @pytest.mark.run(order=122)
    def test_122_NIOS_80612_add_the_DNS_DHCP_NIOS_Grid_license(member):
        
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:')
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('set temp_license')
        child.expect(':')
        child.sendline('1')
        child.expect(':')
        child.sendline('y')
        child.expect(':')
        child.sendline('y')
        child.sendline('y')
        child.expect('Infoblox >')
        child.sendline('set temp_license')
        child.expect(':')
        child.sendline('2')
        child.expect(':')
        child.sendline('y')
        child.expect(': ')
        child.sendline('y')
        child.sendline('y')
        child.sendline('y')
        child.expect('Infoblox >')
        child.sendline('set temp_license')
        child.expect(':')
        child.sendline('7')
        child.expect(':')
        child.sendline('y')
        child.expect(':')
        child.sendline('y')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        sleep(150)
        
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('set temp_license')
        child.expect(':')
        child.sendline('4')
        child.expect(':')
        child.sendline('y')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        sleep(150)
        
        
    @pytest.mark.run(order=123)
    def test_123_NIOS_80612_Create_Auth_zone(self):
        display_msg("Create auth zone with member assignment")

        data = {"fqdn":"nbc.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth",  fields=json.dumps(data),grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==402:

            assert False
        else:

            assert True


    @pytest.mark.run(order=124)
    def test_124_NIOS_80612_Add_Network_10_0_0_0_24_with_members_assignment_in_default_network_view(self):
        print("\n***************************************************")
        print("* TC : 122 - Add network 10.0.0.0/24 with members assignment in default network view *")
        print("*****************************************************")
        data = {"network": "10.0.0.0/24","network_view": "default","members":[{"_struct": "dhcpmember","ipv4addr":config.grid_vip}]}
        #data = {"network": "10.0.0.0/24","network_view": "default","members": [{"_struct": "dhcpmember","ipv4addr": config.grid_master_vip}]}
        response = ib_NIOS.wapi_request('POST', object_type='network', fields=json.dumps(data))
        print(response)
        if bool(re.match("\"network*.*10.0.0.0",str(response))):
                print("Network 10.0.0.0/24 creation successful")
        sleep(5)


    @pytest.mark.run(order=125)
    def test_125_NIOS_80612_Download_Grid_Master_support_bundle(self):
                log("start","/var/log/syslog",config.grid_vip)
                logging.info("Download Grid Master Support Bundle")
                child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
                child.logfile=sys.stdout
                child.expect('password:')
                child.sendline('infoblox')
                child.expect('Infoblox >')
                child.sendline('set transfer_supportbundle scp '+config.client_ip+' root infoblox dest /tmp/support_bundle_master.gz core_files')
                child.expect(':')
                child.sendline('y')
                sleep(100)
                child.expect('Infoblox >')
                response=child.before
                assert re.search(r'supportBundle is uploaded to scp server.* successfully',response)
                print("Test Case 125 Execution Completed")

    @pytest.mark.run(order=126)
    def test_126_test_NIOS_80612__Validate_sys_log_for_errors(self):
        display_msg("Validate var/log/syslog for errors ")
        log("stop","/var/log/syslog",config.grid_vip)
        log1=logv("/bin/tar:","/var/log/syslog",config.grid_vip)
        if log1 :
            display_msg("Error log message found")
            assert False
        else:
            display_msg("No Error logs found")
            assert True
