# Phantom App imports
import phantom.app as phantom
import base64
import json
import requests
import sys
import time

from atd_consts import *
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault


# Define ATD API information
def b64(user, password):
    creds = user + ':' + password
    return base64.b64encode(creds)


def sessionsetup(creds, url_base):
    requests.packages.urllib3.disable_warnings()
    sessionheaders = { 'VE-SDK-API': creds,
                       'Content-Type': 'application/json',
                       'Accept': 'application/vnd.ve.v1.0+json' }
    r = requests.get(url_base + "session.php", headers=sessionheaders, verify=False)
    data = r.json()
    results = data.get('results')
    headers = { 'VE-SDK-API': base64.b64encode(results['session'] + ':' + results['userId']),
                'Accept': 'application/vnd.ve.v1.0+json',
                'accept-encoding': 'gzip;q=0,deflate,sdch'}
    return headers


def profiles(sessionheaders, url_base):
    r = requests.get(url_base + "vmprofiles.php", headers=sessionheaders, verify=False)  # noqa
    # print r
    # response = r.json()
    # for item in response['results']:
    #     print(item['name'].encode('ascii'), item['vmProfileid'])


def submit_file(sessionheaders, ifile, profileID, url_base):
    payload = {'data': {'vmProfileList': profileID, 'submitType': 0}, 'amas_filename': 'test.exe'}
    data = json.dumps(payload)
    files = {'amas_filename': open(ifile, 'rb')}
    r = requests.post(url_base + "fileupload.php", headers=sessionheaders, files=files, data={'data': data}, verify=False)
    response = r.json()
    for line in response['results']:
        taskid = line['taskId']
    return taskid


def get_report(sessionheaders, taskid, url_base, itype, bc):
    payload = {'iTaskId': taskid, 'iType': 'json'}
    try:
        r = requests.get(url_base + "showreport.php", params=payload, headers=sessionheaders, verify=False)
    except Exception as e:
        self.debug_print('Can not get report of this taskid: %d,\nReturned error: %s ' % (taskid, e))
    if r.status_code == 400:
        self.debug_print('Inspection not yet finished')
    data = json.loads(r.content)
    return data


def logout(sessionheaders, url_base):
    r = requests.delete(url_base + "session.php", headers=sessionheaders, verify=False)  # noqa
    # print r.json()


# Define the App Class
class ATDConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ATDConnector, self).__init__()

    def _test_connectivity(self, param):

        config = self.get_config()

        # Get Variables
        atd_ip = config.get(ATD_IP)
        atd_user = config.get(ATD_USER)
        atd_pw = config.get(ATD_PW)

        if (not atd_ip):
            self.save_progress("No ATD IP Defined.")
            return self.get_status()

        if (not atd_user):
            self.save_progress("No ATD User Defined.")
            return self.get_status()

        if (not atd_pw):
            self.save_progress("No ATD Password Defined.")
            return self.get_status()

        self.save_progress("Testing the ATD connectivity")

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, atd_ip)

        try:
            creds = b64(atd_user, atd_pw)
            atdurl = "https://" + atd_ip + "/php/"
            headers = sessionsetup(creds, atdurl)
            profiles(headers, atdurl)
            logout(headers, atdurl)

        except:
            self.set_status(phantom.APP_ERROR, ATD_ERR_SERVER_CONNECTION)
            self.append_to_message(ATD_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, ATD_SUCC_CONNECTIVITY_TEST)

    def _handle_detonate_file(self, param):

        # Push IP Address over the McAfee Data Exchange Layer (DXL)

        config = self.get_config()
        self.debug_print("param", param)

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        itype = ''
        atd_ip = config.get(ATD_IP)
        atd_user = config.get(ATD_USER)
        atd_pw = config.get(ATD_PW)
        atd_profile = config.get(ATD_PROFILE)
        atd_vaultid = param[ATD_VAULTID]

        try:
            # Placeholder to get the file from the vault
            try:
                filepath = Vault.get_file_path(atd_vaultid)
            except:
                return action_result.set_status(phantom.APP_ERROR, 'File not found in vault ("{}")'.format(atd_vaultid))

            creds = b64(atd_user, atd_pw)
            atdurl = "https://" + atd_ip + "/php/"
            headers = sessionsetup(creds, atdurl)
            taskid = submit_file(headers, filepath, atd_profile, atdurl)
            while True:
                try:
                    report = get_report(headers, taskid, atdurl, itype, self)
                    break
                except:
                    time.sleep(30)
                    pass

            logout(headers, atdurl)
            action_result.add_data(report)
            action_result.set_status(phantom.APP_SUCCESS, ATD_SUCC_QUERY)

            date = report['Summary']['Subject']['Timestamp']
            name = report['Summary']['Subject']['Name']
            sha1 = report['Summary']['Subject']['sha-1']
            type = report['Summary']['Subject']['Type']
            size = report['Summary']['Subject']['size']
            verdict = report['Summary']['Verdict']['Description']
            severity = report['Summary']['Verdict']['Severity']
            summary = {'date': date, 'name': name, 'sha1': sha1, 'type': type, 'size': size, 'verdict': verdict, 'severity': severity}

            action_result.update_summary(summary)

        except:
            action_result.set_status(phantom.APP_ERROR, ATD_ERR_QUERY)
            return action_result.get_status()

        return action_result.get_status()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == "detonate_file"):
            ret_val = self._handle_detonate_file(param)
        elif (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ATDConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
