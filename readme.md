[comment]: # "Auto-generated SOAR connector documentation"
# McAfee Advanced Threat Defense \(ATD\)

Publisher: Martin Ohl  
Connector Version: 1\.2\.1  
Product Vendor: McAfee  
Product Name: ATD  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.2\.7532  

This app supports multiple investigative actions on the McAfee ATD appliance

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ATD asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**atd\_ip** |  required  | string | McAfee ATD IP/URL
**verify\_server\_cert** |  required  | boolean | Verify server certificate
**atd\_user** |  required  | string | Username
**atd\_pw** |  required  | password | ATD Password
**atd\_profile** |  required  | numeric | ATD Analyser Profile

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[detonate file](#action-detonate-file) - Run the file in the sandbox and retrieve the analysis results  
[detonate url](#action-detonate-url) - URL link is processed inside analyzer VM and retrieve the analysis results  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'detonate file'
Run the file in the sandbox and retrieve the analysis results

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to detonate | string |  `vault id`  `sha1` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.data\.\*\.Summary\.ATDml\_Prediction\.\*\.ATDml\_Verdict | string | 
action\_result\.data\.\*\.Summary\.ATDml\_Prediction\.\*\.ATDml\_factor | string | 
action\_result\.data\.\*\.Summary\.Attachments | string | 
action\_result\.data\.\*\.Summary\.Bait | string | 
action\_result\.data\.\*\.Summary\.Behavior | string | 
action\_result\.data\.\*\.Summary\.DETversion | string | 
action\_result\.data\.\*\.Summary\.Data\.analysis\_seconds | string | 
action\_result\.data\.\*\.Summary\.Data\.compiled\_with | string | 
action\_result\.data\.\*\.Summary\.Data\.sandbox\_analysis | string | 
action\_result\.data\.\*\.Summary\.Environment | string | 
action\_result\.data\.\*\.Summary\.Files\.\*\.FileType | string | 
action\_result\.data\.\*\.Summary\.Files\.\*\.Md5 | string |  `md5` 
action\_result\.data\.\*\.Summary\.Files\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Files\.\*\.Processes\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Files\.\*\.Processes\.\*\.RelType | string | 
action\_result\.data\.\*\.Summary\.Files\.\*\.Processes\.\*\.Sha256 | string |  `sha256` 
action\_result\.data\.\*\.Summary\.Files\.\*\.Sha1 | string |  `sha1` 
action\_result\.data\.\*\.Summary\.Files\.\*\.Sha256 | string |  `sha256` 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Category | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Functional | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Ipv4 | string |  `ip` 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Port | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Processes\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Processes\.\*\.RelType | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Processes\.\*\.Sha256 | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Reputation | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Risk | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.JSONversion | string | 
action\_result\.data\.\*\.Summary\.MISversion | string |  `ip` 
action\_result\.data\.\*\.Summary\.OSversion | string | 
action\_result\.data\.\*\.Summary\.Process\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Process\.\*\.Reason | string |  `file name` 
action\_result\.data\.\*\.Summary\.Process\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Directories Created/Opened | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Directories Removed | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Copied | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Created | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Deleted | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Modified | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Moved | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Opened | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Read | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Memory Mapped Files | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Other | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Network Operations\.\*\.DNS Queries | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Network Operations\.\*\.Other | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Network Operations\.\*\.Socket Activities | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Other Operations\.\*\.Others | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Other Operations\.\*\.Signal Objects | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Other | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Process Created | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Process Opened | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Process killed | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Thread Created | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Created | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Deleted | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Modified | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Opened | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Read | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Run\-Time Dlls\.\*\.DLL Loaded | string | 
action\_result\.data\.\*\.Summary\.Properties\.comments | string | 
action\_result\.data\.\*\.Summary\.Properties\.copyright | string | 
action\_result\.data\.\*\.Summary\.Properties\.description | string | 
action\_result\.data\.\*\.Summary\.Properties\.file\_version | string | 
action\_result\.data\.\*\.Summary\.Properties\.internal\_name | string | 
action\_result\.data\.\*\.Summary\.Properties\.original\_name | string | 
action\_result\.data\.\*\.Summary\.Properties\.product\_name | string | 
action\_result\.data\.\*\.Summary\.Properties\.publisher | string | 
action\_result\.data\.\*\.Summary\.Properties\.signature | string | 
action\_result\.data\.\*\.Summary\.Properties\.strong\_name | string | 
action\_result\.data\.\*\.Summary\.Properties\.version\_info | string | 
action\_result\.data\.\*\.Summary\.SUMversion | string |  `ip` 
action\_result\.data\.\*\.Summary\.Selectors\.\*\.Engine | string | 
action\_result\.data\.\*\.Summary\.Selectors\.\*\.MalwareName | string | 
action\_result\.data\.\*\.Summary\.Selectors\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.Stats\.\*\.Category | string | 
action\_result\.data\.\*\.Summary\.Stats\.\*\.ID | string | 
action\_result\.data\.\*\.Summary\.Stats\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.Subject\.FileType | string | 
action\_result\.data\.\*\.Summary\.Subject\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Subject\.Timestamp | string | 
action\_result\.data\.\*\.Summary\.Subject\.Type | string | 
action\_result\.data\.\*\.Summary\.Subject\.md5 | string |  `md5` 
action\_result\.data\.\*\.Summary\.Subject\.parent\_archive | string | 
action\_result\.data\.\*\.Summary\.Subject\.sha\-1 | string |  `sha1` 
action\_result\.data\.\*\.Summary\.Subject\.sha\-256 | string |  `sha256` 
action\_result\.data\.\*\.Summary\.Subject\.size | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.category | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.functional | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.port | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.reputation | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.risk | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.severity | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.url | string |  `ip` 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Category | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Functional | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Port | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Processes\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Processes\.\*\.RelType | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Processes\.\*\.Sha256 | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Reputation | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Risk | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Url | string | 
action\_result\.data\.\*\.Summary\.Verdict\.Description | string | 
action\_result\.data\.\*\.Summary\.Verdict\.Severity | string | 
action\_result\.data\.\*\.Summary\.hasDynamicAnalysis | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
URL link is processed inside analyzer VM and retrieve the analysis results

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**atd\_suburl** |  required  | URL to detonate | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.atd\_suburl | string |  `url` 
action\_result\.data\.\*\.Summary\.Bait | string | 
action\_result\.data\.\*\.Summary\.Behavior | string | 
action\_result\.data\.\*\.Summary\.DETversion | string | 
action\_result\.data\.\*\.Summary\.Data\.analysis\_seconds | string | 
action\_result\.data\.\*\.Summary\.Data\.compiled\_with | string | 
action\_result\.data\.\*\.Summary\.Data\.sandbox\_analysis | string | 
action\_result\.data\.\*\.Summary\.Environment | string | 
action\_result\.data\.\*\.Summary\.Files\.\*\.FileType | string | 
action\_result\.data\.\*\.Summary\.Files\.\*\.Md5 | string | 
action\_result\.data\.\*\.Summary\.Files\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Files\.\*\.Processes\.\*\.Name | string |  `url`  `file name` 
action\_result\.data\.\*\.Summary\.Files\.\*\.Processes\.\*\.RelType | string | 
action\_result\.data\.\*\.Summary\.Files\.\*\.Processes\.\*\.Sha256 | string |  `sha256` 
action\_result\.data\.\*\.Summary\.Files\.\*\.Sha1 | string | 
action\_result\.data\.\*\.Summary\.Files\.\*\.Sha256 | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Category | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Functional | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Ipv4 | string |  `ip` 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Port | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Processes\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Processes\.\*\.RelType | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Processes\.\*\.Sha256 | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Reputation | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Risk | string | 
action\_result\.data\.\*\.Summary\.Ips\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.JSONversion | string | 
action\_result\.data\.\*\.Summary\.MISversion | string |  `ip` 
action\_result\.data\.\*\.Summary\.OSversion | string | 
action\_result\.data\.\*\.Summary\.Process\.\*\.Name | string |  `url`  `file name` 
action\_result\.data\.\*\.Summary\.Process\.\*\.Reason | string | 
action\_result\.data\.\*\.Summary\.Process\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Created | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Modified | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Files Read | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Memory Mapped Files | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.File Operations\.\*\.Other | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Name | string |  `url` 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Network Operations\.\*\.DNS Queries | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Network Operations\.\*\.Other | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Network Operations\.\*\.Socket Activities | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Other Operations\.\*\.Others | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Other Operations\.\*\.Signal Objects | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Other | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Process Created | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Process Opened | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Process Operations\.\*\.Thread Created | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Created | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Deleted | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Modified | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Opened | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Registry Operations\.\*\.Registry Read | string | 
action\_result\.data\.\*\.Summary\.Processes\.\*\.Run\-Time Dlls\.\*\.DLL Loaded | string | 
action\_result\.data\.\*\.Summary\.SUMversion | string |  `ip` 
action\_result\.data\.\*\.Summary\.Selectors\.\*\.Engine | string | 
action\_result\.data\.\*\.Summary\.Selectors\.\*\.MalwareName | string | 
action\_result\.data\.\*\.Summary\.Selectors\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.Stats\.\*\.Category | string | 
action\_result\.data\.\*\.Summary\.Stats\.\*\.ID | string | 
action\_result\.data\.\*\.Summary\.Stats\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.Subject\.FileType | string | 
action\_result\.data\.\*\.Summary\.Subject\.Name | string |  `url` 
action\_result\.data\.\*\.Summary\.Subject\.Timestamp | string | 
action\_result\.data\.\*\.Summary\.Subject\.Type | string | 
action\_result\.data\.\*\.Summary\.Subject\.md5 | string |  `md5` 
action\_result\.data\.\*\.Summary\.Subject\.parent\_archive | string | 
action\_result\.data\.\*\.Summary\.Subject\.sha\-1 | string |  `sha1` 
action\_result\.data\.\*\.Summary\.Subject\.sha\-256 | string |  `sha256` 
action\_result\.data\.\*\.Summary\.Subject\.size | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.category | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.functional | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.port | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.reputation | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.risk | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.severity | string | 
action\_result\.data\.\*\.Summary\.URL\_Reputation\.\*\.url | string |  `ip`  `url` 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Category | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Functional | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Port | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Processes\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Processes\.\*\.RelType | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Processes\.\*\.Sha256 | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Reputation | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Risk | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Severity | string | 
action\_result\.data\.\*\.Summary\.Urls\.\*\.Url | string | 
action\_result\.data\.\*\.Summary\.Verdict\.Description | string | 
action\_result\.data\.\*\.Summary\.Verdict\.Severity | string | 
action\_result\.data\.\*\.Summary\.hasDynamicAnalysis | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 