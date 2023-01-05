import re
import config
import pytest
import unittest
import logging
import json
import subprocess
import os
from time import sleep
import ib_utils.ib_NIOS as ib_NIOS
from time import sleep
import pexpect
import paramiko
from ib_utils.start_stop_logs import log_action as log
from ib_utils.file_content_validation import log_validation as logv
import ib_utils.common_utilities as common_util

logging.basicConfig(filename='nios-86222.log', filemode='w', level=logging.DEBUG)

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

    @pytest.mark.run(order=303)
    def test_303_NIOS_84672_Create_an_auth_zone(self):
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

    
    @pytest.mark.run(order=304)
    def test_304_NIOS_84672_Add_A_record_to_the_auth_zone(self):
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


    @pytest.mark.run(order=305)
    def test_305_NIOS_84672_Perform_dig_query_on_the_A_record_from_the_grid(self):
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

    @pytest.mark.run(order=306)
    def test_306_NIOS_84672_Validate_if_core_files_were_generated_after_dig_operation(self):
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

    @pytest.mark.run(order=307)
    def test_307_NIOS_84694_81654_Perform_nsupdate_from_the_grid(self):
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

    @pytest.mark.run(order=308)
    def test_308_NIOS_84694_81654_Validate_if_core_files_were_generated_after_nsupdate_operation(self):
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

    @pytest.mark.run(order=309)
    def test_309_NIOS_83213_Add_ALIAS_Record_of_type_A_record(self):
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

    @pytest.mark.run(order=310)
    def test_310_NIOS_83213_Perform_dig_operation_on_the_ALIAS_record(self):
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

    @pytest.mark.run(order=311)
    def test_311_NIOS_83213_Validate_if_core_files_were_generated_after_dig_operation(self):
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


    @pytest.mark.run(order=312)
    def test_312_NIOS_82043_Set_return_minimal_responses_to_false_on_member_dns(self):
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

    @pytest.mark.run(order=313)
    def test_313_NIOS_82043_Perform_dig_query_and_check_if_additional_sections_are_returned_in_the_response(self):
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

        
    @pytest.mark.run(order=314)
    def test_314_NIOS_82043_Set_return_minimal_responses_to_true_on_member_dns(self):
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

#"""
#Below testcases have been coded from 7th Dec 2022
#"""

    @pytest.mark.run(order=315)
    def test_315_NIOS_85705_Check_if_temporary_failure_in_name_resolution_logs_are_observerd_in_infoblox_logs(self):
        display_msg("Check if 'Temporary failure in name resolution' logs are observed in infoblox.log")
        display_msg("Starting log capture on infoblox.log")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        display_msg("Sleep for 2min for log capture")
        sleep(120)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        display_msg("Log capture complete")
        display_msg("Check if error logs are seen")
        if logv(".*Temporary failure in name resolution.*","/infoblox/var/infoblox.log",config.grid_vip) :
            display_msg("'Temporary failure in name resolution' logs are observed in infoblox.log")
            assert False
        else:
            display_msg("'Temporary failure in name resolution' logs are not observed in infoblox.log")
            assert True

    @pytest.mark.run(order=316)
    def test_316_NIOS_87645_create_an_auth_zone(self):
        display_msg("Create an Auth zone")

        data = {"fqdn":"nios87645.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Create authoratative zone.")
            assert False
        else:
            dns_restart_services()
            display_msg("\n--------------------------------------------------------\n")
            display_msg("Validating Authoratative zone - nios87645.com")
            display_msg("\n--------------------------------------------------------\n")

            response = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios87645.com", grid_vip=config.grid_vip)
            response=json.loads(response)[0]
            display_msg(response)

            if 'nios87645.com' in response['_ref']:
                display_msg(response["_ref"])
                display_msg("SUCCESS: Authoratative Zone 'nios87645.com' was created!")
                dns_restart_services()
                assert True
            else:
                display_msg("FAILURE: Authoratative Zone 'nios87645.com' creation failed")
                assert False

    
    @pytest.mark.run(order=317)
    def test_317_NIOS_87645_Export_the_zone_data_in_csv_format(self):
        display_msg("Export the zone data in CSV format")
        data={"_separator":"COMMA","_object": "zone_auth"}
        create_file = ib_NIOS.wapi_request('POST', object_type="fileop",fields=json.dumps(data),params="?_function=csv_export")
        display_msg(create_file)
        res = json.loads(create_file)
        token = json.loads(create_file)['token']
        url = json.loads(create_file)['url']
        display_msg("Create the fileop function to dowload the csv file to the specified url")
        cmd='curl -k1 -u admin:infoblox -H "Content-type:application/force-download" -O %s'%(url)
        result = subprocess.check_output(cmd, shell=True)
        display_msg(result)

    @pytest.mark.run(order=318)
    def test_318_NIOS_87645_Verify_if_the_csv_file_has_been_downloaded(self):
        display_msg("Verify if the csv file has been downloaded")
        try:
            output = subprocess.check_output(["ls","-l"])
        except subprocess.CalledProcessError as e:
            display_msg("Exception encountered when trying to execute the command. Check the error below")
            display_msg(e)
            assert False
        else:
            display_msg(output)
            if 'Authzones.csv' in output:
                display_msg("CSV export successfull")
                assert True
            else:
                display_msg("CSV export unsuccessful")
                assert False

    @pytest.mark.run(order=319)
    def test_319_NIOS_87645_Delete_the_auth_zone(self):
        display_msg("Delete the auth zone")
        response = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios87645.com", grid_vip=config.grid_vip)
        display_msg(response)
        ref = json.loads(response)[0]['_ref']
        del_ref = ib_NIOS.wapi_request('DELETE', object_type = ref)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Deleting zone failed.")
            assert False
        else:
            dns_restart_services()
            display_msg("Auth zone deletion successful")
            assert True

    @pytest.mark.run(order=320)
    def test_320_NIOS_87645_Import_the_exported_csv_file_and_check_if_no_errors_are_observed(self):
        display_msg("Import the exported CSV file and check if no errors are observed")
        dir_name = os.getcwd()
        base_filename = "Authzones.csv"
        token = common_util.generate_token_from_file(dir_name, base_filename)
        display_msg(token)
        data = {"token": token,"action":"START", "doimport":True, "on_error":"CONTINUE","update_method":"ADD"}
        response = ib_NIOS.wapi_request('POST', object_type="fileop", fields=json.dumps(data),params="?_function=csv_import")
        response=json.loads(response)
        display_msg(response)
        sleep(10)
        data={"action":"START","file_name":base_filename,"on_error":"CONTINUE","operation":"CREATE","separator":"COMMA"}
        get_ref=ib_NIOS.wapi_request('GET', object_type="csvimporttask")
        display_msg(get_ref)
        get_ref=json.loads(get_ref)
        for ref in get_ref:
            if response["csv_import_task"]["import_id"]==ref["import_id"]:
                if ref["lines_failed"]==0:
                    logging.info("CSV import successful")
                    dns_restart_services()
                    assert True
                else:
                    display_msg("CSV import unsuccessful")
                    assert False

    @pytest.mark.run(order=321)
    def test_321_NIOS_87645_Delete_the_zone_and_csv_file(slef):
        display_msg("Delete the zone and csv file")
        count = 0
        display_msg("Delete the auth zone")
        response = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios87645.com", grid_vip=config.grid_vip)
        display_msg(response)
        ref = json.loads(response)[0]['_ref']
        del_ref = ib_NIOS.wapi_request('DELETE', object_type = ref)
        display_msg(del_ref)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Deleting zone failed.")
        else:
            dns_restart_services()
            display_msg("Auth zone deletion successful")
            count += 1

        display_msg("Delete the exported csv file")
        path = os.getcwd() + "/Authzones.csv"
        try:
            subprocess.check_output(['rm','-rf',path])
        except subprocess.CalledProcessError as e:
            display_msg("Error encountered while deleting the csv file. Check below for more details")
            display_msg(e)
        else:
            display_msg("CSV file deleted successfully")
            count += 1

        if count == 2:
            display_msg("Cleanup successful")
            assert True
        else:
            display_msg("Cleanup unsuccessful")
            assert False

    
    @pytest.mark.run(order=322)
    def test_322_NIOS_83043_Set_the_KSK_and_ZSK_algo_to_ECDSAP256SHA256_in_DNSSEC_properties(self):
        display_msg("Set the KSK and ZSK algo to ECDSAP256SHA256 in DNSSEC properties")
        data = {"dnssec_key_params": {"ksk_algorithms":[{"algorithm": "ECDSAP256SHA256","size": 256}],"zsk_algorithms":[{"algorithm": "ECDSAP256SHA256","size": 256}]}}
        response = ib_NIOS.wapi_request('GET', object_type="grid:dns", grid_vip=config.grid_vip)
        display_msg(response)
        grid_dns_ref = json.loads(response)[0]["_ref"]
        response = ib_NIOS.wapi_request('PUT', object_type=grid_dns_ref,fields=json.dumps(data))
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("Unable to change the KSK and ZSK algo to ECDSAP256SHA256")
            assert False
        else:
            display_msg("KSK and ZSK algo changed to ECDSAP256SHA256")
            dns_restart_services()
            assert True

        
    @pytest.mark.run(order=323)
    def test_323_NIOS_83043_Verify_KSK_and_ZSK_algo_set_to_ECDSAP256SHA256_in_DNSSEC_properties(self):
        display_msg("Verify KSK and ZSK algo set to ECDSAP256SHA256 in DNSSEC properties")
        response = ib_NIOS.wapi_request('GET', object_type="grid:dns?_return_fields=dnssec_key_params", grid_vip=config.grid_vip)
        display_msg(response)
        response = json.loads(response)
        if (response[0]["dnssec_key_params"]["ksk_algorithms"][0]["algorithm"] == "ECDSAP256SHA256" and response[0]["dnssec_key_params"]["zsk_algorithms"][0]["algorithm"] == "ECDSAP256SHA256") :
            display_msg("ECDSAP256SHA256 algorithm present")
            assert True
        else:
            display_msg("ECDSAP256SHA256 algorithm not present")
            assert False


    @pytest.mark.run(order=324)
    def test_324_NIOS_83043_Set_the_KSK_and_ZSK_algo_to_ECDSAP384SHA384_in_DNSSEC_properties(self):
        display_msg("Set the KSK and ZSK algo to ECDSAP384SHA384 in DNSSEC properties")
        data = {"dnssec_key_params": {"ksk_algorithms":[{"algorithm": "ECDSAP384SHA384","size": 256}],"zsk_algorithms":[{"algorithm": "ECDSAP384SHA384","size": 256}]}}
        response = ib_NIOS.wapi_request('GET', object_type="grid:dns", grid_vip=config.grid_vip)
        display_msg(response)
        grid_dns_ref = json.loads(response)[0]["_ref"]
        response = ib_NIOS.wapi_request('PUT', object_type=grid_dns_ref,fields=json.dumps(data))
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("Unable to change the KSK and ZSK algo to ECDSAP384SHA384")
            assert False
        else:
            display_msg("KSK and ZSK algo changed to ECDSAP384SHA384")
            dns_restart_services()
            assert True

        
    @pytest.mark.run(order=325)
    def test_325_NIOS_83043_Verify_KSK_and_ZSK_algo_set_to_ECDSAP384SHA384_in_DNSSEC_properties(self):
        display_msg("Verify KSK and ZSK algo set to ECDSAP384SHA384 in DNSSEC properties")
        response = ib_NIOS.wapi_request('GET', object_type="grid:dns?_return_fields=dnssec_key_params", grid_vip=config.grid_vip)
        display_msg(response)
        response = json.loads(response)
        if (response[0]["dnssec_key_params"]["ksk_algorithms"][0]["algorithm"] == "ECDSAP384SHA384" and response[0]["dnssec_key_params"]["zsk_algorithms"][0]["algorithm"] == "ECDSAP384SHA384") :
            display_msg("ECDSAP384SHA384 algorithm present")
            assert True
        else:
            display_msg("ECDSAP384SHA384 algorithm not present")
            assert False

    @pytest.mark.run(order=326)
    def test_326_NIOS_83711_Check_if_we_are_not_able_to_select_RSA_MD5_algo_with_NSEC(self):
        display_msg("Check if we are not able to select RSA\MD5 algo with NSEC")
        data = {"dnssec_key_params": {"next_secure_type": "NSEC","ksk_algorithms":[{"algorithm": "RSAMD5","size": 1024}]}}
        response = ib_NIOS.wapi_request('GET', object_type="grid:dns?_return_fields=dnssec_key_params", grid_vip=config.grid_vip)
        display_msg(response)
        grid_dns_ref = json.loads(response)[0]['_ref']
        response = ib_NIOS.wapi_request('PUT', object_type=grid_dns_ref,fields=json.dumps(data))
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("Unable to set the RSA/MD5 algo as expected")
            assert True
        else:
            display_msg("RSA/MD5 algo has been set, which is not the correct behaviour")
            assert False

    @pytest.mark.run(order=327)
    def test_327_NIOS_87135_Add_an_auth_zone(self):
        display_msg("Create an Auth zone")

        data = {"fqdn":"nios87135.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Create authoratative zone.")
            assert False
        else:
            dns_restart_services()
            display_msg("\n--------------------------------------------------------\n")
            display_msg("Validating Authoratative zone - nios87135.com")
            display_msg("\n--------------------------------------------------------\n")

            response = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios87135.com", grid_vip=config.grid_vip)
            response=json.loads(response)[0]
            display_msg(response)

            if 'nios87135.com' in response['_ref']:
                display_msg(response["_ref"])
                display_msg("SUCCESS: Authoratative Zone 'nios87135.com' was created!")
                dns_restart_services()
                assert True
            else:
                display_msg("FAILURE: Authoratative Zone 'nios87135.com' creation failed")
                assert False

    @pytest.mark.run(order=328)
    def test_328_NIOS_87135_Sign_the_zone_nios87135_com(self):
        display_msg("Sign the zone nios87135.com")
        zone_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios87135.com", grid_vip=config.grid_vip)
        display_msg(zone_ref)
        zone_ref = json.loads(zone_ref)[0]['_ref']
        data={"buffer":"KSK","operation":"SIGN"}
        response = ib_NIOS.wapi_request('POST', object_type=zone_ref,fields=json.dumps(data),params="?_function=dnssec_operation")
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Failed to sign the zone nios87135.com.")
            assert False
        else:
            display_msg("Zone nios87135.com signed successfully")
            dns_restart_services()
            assert True

    @pytest.mark.run(order=329)
    def test_329_NIOS_87135_Validate_if_zone_signing_was_successful(self):
        display_msg("Verify if zone signing was successful")
        zone_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios87135.com", grid_vip=config.grid_vip)
        display_msg(zone_ref)
        zone_ref = json.loads(zone_ref)[0]['_ref']
        data = {"fqdn":"nios87135.com"}
        response = ib_NIOS.wapi_request('GET', object_type= zone_ref + "?_return_fields=is_dnssec_signed",fields=json.dumps(data))
        display_msg(response)
        if json.loads(response)["is_dnssec_signed"] == True:
            display_msg("Zone signing verification successful")
            assert True
        else:
            display_msg("Zone signing verification failed")
            assert False

    @pytest.mark.run(order=330)
    def test_330_NIOS_87315_Change_the_NSEC3_salt_length_of_the_zone_nios87315(self):
        display_msg("Change the NSEC3 salt length of zone nios87315.com")
        zone_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios87135.com", grid_vip=config.grid_vip)
        for zone in json.loads(zone_ref):
            if 'nios87135.com' in zone['_ref']:
                display_msg(zone)
                zone_ref = zone['_ref']
                break
        data = {"dnssec_key_params":{"nsec3_salt_min_length": 2,"nsec3_salt_max_length": 14}}
        response = ib_NIOS.wapi_request('PUT', object_type=zone_ref,fields=json.dumps(data))
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("Error encountered while changing NSEC3 salt length")
            assert False
        else:
            display_msg("NSEC3 salt length change successfull, proceeding with DNS restart")
            dns_restart_services()
            display_msg("DNS service restart successfull")
            assert True

    @pytest.mark.run(order=331)
    def test_331_NIOS_87315_Verify_the_NSEC3_salt_length_change(self):
        display_msg("Change the NSEC3 salt length of zone nios87315.com")
        zone_ref = ib_NIOS.wapi_request('GET', object_type="zone_auth?_return_fields=dnssec_key_params", grid_vip=config.grid_vip)
        for zone in json.loads(zone_ref):
            if 'nios87135.com' in zone['_ref']:
                display_msg(zone)
                zone_ref = zone
                break
        if zone_ref["dnssec_key_params"]["nsec3_salt_min_length"] == 2 and zone_ref["dnssec_key_params"]["nsec3_salt_max_length"] == 14:
            display_msg("Changing NSEC3 salt length successful")
            assert True
        else:
            display_msg("NSEC3 salt length change failed")
            assert False

    @pytest.mark.run(order=332)
    def test_332_NIOS_87315_Delete_the_auth_zone(self):
        response = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios87135.com", grid_vip=config.grid_vip)
        display_msg(response)
        ref = json.loads(response)[0]['_ref']
        del_ref = ib_NIOS.wapi_request('DELETE', object_type = ref)
        display_msg(del_ref)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Deleting zone failed.")
            assert False
        else:
            dns_restart_services()
            display_msg("Auth zone deletion successful")
            assert True

    @pytest.mark.run(order=333)
    def test_333_NIOS_86900_Add_auth_zone(self):
        display_msg("Create an Auth zone")

        data = {"fqdn":"nios86900.com","view":"default","grid_primary":[{"name":config.grid_fqdn}]}
        response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data), grid_vip=config.grid_vip)
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Create authoratative zone.")
            assert False
        else:
            dns_restart_services()
            display_msg("\n--------------------------------------------------------\n")
            display_msg("Validating Authoratative zone - nios86900.com")
            display_msg("\n--------------------------------------------------------\n")

            response = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios86900.com", grid_vip=config.grid_vip)
            response=json.loads(response)[0]
            display_msg(response)

            if 'nios86900.com' in response['_ref']:
                display_msg(response["_ref"])
                display_msg("SUCCESS: Authoratative Zone 'nios86900.com' was created!")
                dns_restart_services()
                assert True
            else:
                display_msg("FAILURE: Authoratative Zone 'nios86900.com' creation failed")
                assert False

    @pytest.mark.run(order=334)
    def test_334_NIOS_86900_Add_RR_of_type_APL_and_check_no_error_logs_are_observed(self):
        display_msg("Add RR of type APL and check no error logs are observed")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        data={"name": "apl.nios86900.com","record_type": "APL","subfield_values": [{"field_type": "P","field_value": "1:224.0.0.0/4 2:ff00::/8","include_length": "NONE"}],"view": "default"}
        response = ib_NIOS.wapi_request('POST', object_type="record:unknown",fields=json.dumps(data))
        display_msg(response)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("Error encountered while trying to add APL record")
            assert False
        sleep(10)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        count = 0
        if logv(".*ERROR com.infoblox.widget.dialog.function.FunctionImpl:126 - inheritance invocation target exception.*","/infoblox/var/infoblox.log",config.grid_vip):
            count +=1
            display_msg("Encountered error ERROR com.infoblox.widget.dialog.function.FunctionImpl:126 - inheritance invocation target exception")  

        if logv(".*Missing: record_rdata_hash.*","/infoblox/var/infoblox.log",config.grid_vip):
            count +=1
            display_msg("Encountered error Missing: record_rdata_hash")

        if count == 0:
            display_msg("No error logs encountered while adding APL record")
            assert True
        else:
            assert False

    @pytest.mark.run(order=335)
    def test_335_NIOS_86900_Delete_the_auth_zone(self):
        response = ib_NIOS.wapi_request('GET', object_type="zone_auth?fqdn=nios86900.com", grid_vip=config.grid_vip)
        display_msg(response)
        ref = json.loads(response)[0]['_ref']
        del_ref = ib_NIOS.wapi_request('DELETE', object_type = ref)
        display_msg(del_ref)
        if response[0]==400 or response[0]==401 or response[0]==404 or response[0]==500:
            display_msg("FAILURE: Deleting zone failed.")
            assert False
        else:
            dns_restart_services()
            display_msg("Auth zone deletion successful")
            assert True
















    















