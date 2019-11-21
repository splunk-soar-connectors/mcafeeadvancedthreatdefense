# Phantom App imports
import phantom.app as phantom
import requests
import json
import base64
import time

from atd_consts import *
from bs4 import UnicodeDammit
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


# Define ATD API information
def b64(user, password):
    creds = user + ':' + password
    return base64.b64encode(creds)


def sessionsetup(creds, url_base, verify):
    sessionheaders = { 'VE-SDK-API': creds,
                                    'Content-Type': 'application/json',
                                    'Accept': 'application/vnd.ve.v1.0+json' }
    r = requests.get(url_base + "session.php", headers=sessionheaders, verify=verify)
    data = r.json()
    results = data.get('results')
    headers = { 'VE-SDK-API': base64.b64encode(results['session'] + ':' + results['userId']),
                'Accept': 'application/vnd.ve.v1.0+json',
                'accept-encoding': 'gzip;q=0,deflate,sdch'}
    return headers


def submit_file(sessionheaders, ifile, filename, profileID, url_base, verify):
    payload = {'data': {'vmProfileList': profileID, 'submitType': 0}}
    data = json.dumps(payload)

    try:
       files = {'amas_filename': (filename, open(ifile, 'rb'))}
    except Exception as e:
       self.set_status(phantom.APP_ERROR)
       self.append_to_message('Error opening the file', e)

    try:
       r = requests.post(url_base + "fileupload.php", headers=sessionheaders, files=files, data={'data': data}, verify=verify)
       response = r.json()
       for line in response['results']:
          taskid = line['taskId']
       return taskid
    except Exception as e:
       self.set_status(phantom.APP_ERROR)
       self.append_to_message('Error submitting files to ATD', e)


def submit_url(sessionheaders, suburl, profileID, url_base, verify):
    payload = {'data': {'vmProfileList': profileID, 'submitType': 1, 'url': suburl}}
    data = json.dumps(payload)

    try:
       r = requests.post(url_base + "fileupload.php", headers=sessionheaders, data={'data': data}, verify=verify)
       response = r.json()
       for line in response['results']:
          taskid = line['taskId']
       return taskid
    except Exception as e:
       self.set_status(phantom.APP_ERROR)
       self.append_to_message('Error submitting url to ATD', e)


def get_report(sessionheaders, taskid, url_base, itype, verify):
    payload = {'iTaskId': taskid, 'iType': 'json'}
    try:
        r = requests.get(url_base + "showreport.php", params=payload, headers=sessionheaders, verify=verify)
    except Exception as e:
        print 'Can not get report of this taskid: %d,\nReturned error: %s ' % (taskid, e)
    if r.status_code == 400:
        print 'Inspection not yet finished'
    data = json.loads(r.content)
    return data


def logout(sessionheaders, url_base, verify):
    requests.delete(url_base + "session.php", headers=sessionheaders, verify=verify)


# Define the App Class
class MfeAtdConnector(BaseConnector):

    def __init__(self):

        super(MfeAtdConnector, self).__init__()

        self._state = None
        self._base_url = None

    def initialize(self):

        config = self.get_config()
        self._verify = config.get('verify_server_cert', False)
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
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
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, UnicodeDammit(atd_ip).unicode_markup.encode('utf-8'))

        try:
            creds = b64(atd_user, atd_pw)
            atdurl = "https://" + atd_ip + "/php/"
            headers = sessionsetup(creds, atdurl, self._verify)
            logout(headers, atdurl, self._verify)

        except Exception as e:
            self.set_status(phantom.APP_ERROR, "{}. Error: {}".format(ATD_ERR_SERVER_CONNECTION, str(e)))
            self.append_to_message(ATD_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, ATD_SUCC_CONNECTIVITY_TEST)

    def _handle_detonate_file(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        self.debug_print("param", param)

        itype = ''
        atd_ip = config.get(ATD_IP)
        atd_user = config.get(ATD_USER)
        atd_pw = config.get(ATD_PW)
        atd_profile = config.get(ATD_PROFILE)
        atd_vaultid = param[ATD_VAULTID]

        try:
            # Placeholder to get the file from the vault
            try:
                info = Vault.get_file_info(vault_id=atd_vaultid)
                if not info:
                    return action_result.set_status(phantom.APP_ERROR, 'File not found in vault ("{}")'.format(atd_vaultid))
                if isinstance(info, list):
                    info = info[0]

                filepath = info.get('path')
                if not filepath:
                    return action_result.set_status(phantom.APP_ERROR, "Unable to find a path associated with the provided vault ID")
                filename = info.get('name')
            except:
                return action_result.set_status(phantom.APP_ERROR, 'Error while fetching the vault information of the vault ID: ("{}")'.format(atd_vaultid))

            creds = b64(atd_user, atd_pw)
            atdurl = "https://" + atd_ip + "/php/"
            headers = sessionsetup(creds, atdurl, self._verify)
            taskid = submit_file(headers, filepath, filename, atd_profile, atdurl, self._verify)
            while True:
                try:
                    report = get_report(headers, taskid, atdurl, itype, self._verify)
                    print report
                    break
                except:
                    time.sleep(10)
                    pass

            logout(headers, atdurl, self._verify)
            action_result.add_data(report)
            action_result.set_status(phantom.APP_SUCCESS, ATD_SUCC_QUERY)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, "{}. {}. Error: {}".format(ATD_ERR_SERVER_CONNECTION, ATD_ERR_QUERY, str(e)))
            return action_result.get_status()

        return action_result.get_status()

    def _handle_detonate_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        self.debug_print("param", param)

        itype = ''
        atd_ip = config.get(ATD_IP)
        atd_user = config.get(ATD_USER)
        atd_pw = config.get(ATD_PW)
        atd_profile = config.get(ATD_PROFILE)
        atd_suburl = param[ATD_SUBURL]

        try:
            creds = b64(atd_user, atd_pw)
            atdurl = "https://" + atd_ip + "/php/"
            headers = sessionsetup(creds, atdurl, self._verify)
            taskid = submit_url(headers, atd_suburl, atd_profile, atdurl, self._verify)
            while True:
               try:
                  report = get_report(headers, taskid, atdurl, itype, self._verify)
                  print report
                  break
               except:
                  time.sleep(30)
                  pass

            logout(headers, atdurl, self._verify)
            action_result.add_data(report)
            action_result.set_status(phantom.APP_SUCCESS, ATD_SUCC_QUERY)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, "{}. {}. Error: {}".format(ATD_ERR_SERVER_CONNECTION, ATD_ERR_QUERY, str(e)))
            return action_result.get_status()

        return action_result.get_status()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'detonate_file':
            ret_val = self._handle_detonate_file(param)

        elif action_id == 'detonate_url':
            ret_val = self._handle_detonate_url(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MfeAtdConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
