![DetectionLab](./img/DetectionLabELK-new.jpg)
# DetectionLabELK
DetectionLabELK is a fork from Chris Long's [DetectionLab](https://github.com/clong/DetectionLab) with ELK stack instead of Splunk.


![Maintenance](https://img.shields.io/maintenance/yes/2020.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cyberdefenders/DetectionLabELK.svg?style=flat-square)](https://github.com/cyberdefenders/DetectionLabELK/commit/master)
[![Twitter](https://img.shields.io/twitter/follow/DetectionLab.svg?style=social)](https://twitter.com/DetectionLab)
[![Twitter](https://img.shields.io/twitter/follow/CyberDefenders?style=social)](https://twitter.com/CyberDefenders)


## Lab Information:
* **Domain Name**: windomain.local
* **Windows Admininstrator login**: vagrant:vagrant
* **Fleet login**: https://192.168.38.105:8412 - admin:admin123#
* **Kibana login**: http://192.168.38.105:5601
* **Microsoft ATA login**: https://192.168.38.103 - wef\vagrant:vagrant
* **Guacamole login**: http://192.168.38.105:8080/guacamole - vagrant:vagrant


## Primary Lab Features:
* [Microsoft Advanced Threat Analytics](https://www.microsoft.com/en-us/cloud-platform/advanced-threat-analytics) is installed on the WEF machine, with the lightweight ATA gateway installed on the DC
* Windoes Evenet forwarder along with Winlogbeat are pre-installed and all indexes are pre-created on ELK. Technology add-ons for Windows are also preconfigured.
* A custom Windows auditing configuration is set via GPO to include command line process auditing and additional OS-level logging
* [Palantir's Windows Event Forwarding](http://github.com/palantir/windows-event-forwarding)  subscriptions and custom channels are implemented
* Powershell transcript logging is enabled. All logs are saved to `\\wef\pslogs`
* osquery comes installed on each host and is pre-configured to connect to a [Fleet](https://kolide.co/fleet) server via TLS. Fleet is preconfigured with the configuration from [Palantir's osquery Configuration](https://github.com/palantir/osquery-configuration)
* Sysmon is installed and configured using SwiftOnSecurity’s open-sourced configuration
* All autostart items are logged to Windows Event Logs via [AutorunsToWinEventLog](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog)
* SMBv1 Auditing is enabled


## Requirements
* 55GB+ of free disk space
* 16GB+ of RAM
* Vagrant 2.2.2 or newer
* Virtualbox



## Deployment Options
1.  **Use Vagrant Cloud Boxes - ETA ~2 hours**.
    * [Install Vagrant](https://www.vagrantup.com/downloads.html) on your system.
    * [Install Packer](https://packer.io/downloads.html) on your system.
    * Install the Vagrant-Reload plugin by running the following command: `vagrant plugin install vagrant-reload`.
    * Download DetectionLabELK to your local machine by running `git clone https://github.com/cyberdefenders/DetectionLabELK.git` from command line OR download it directly via [this link](https://github.com/cyberdefenders/DetectionLabELK/archive/master.zip).
    * `cd` to "DetectionLabELK/Vagrant" and execute `vagrant up`.

2.  **Build Boxes From Scratch - ETA ~5 hours**. 
    * [Install Vagrant](https://www.vagrantup.com/downloads.html) on your system.
    * [Install Packer](https://packer.io/downloads.html) on your system.
    * Install "Vagrant-Reload" plugin by running the following command: `vagrant plugin install vagrant-reload`.
    * Download DetectionLabELK to your local machine by running `git clone https://github.com/cyberdefenders/DetectionLabELK.git` from command line OR download it directly via [this link](https://github.com/cyberdefenders/DetectionLabELK/archive/master.zip).
    * `cd` to "DetectionLabELK" base directory and build the lab by executing `./build.sh virtualbox` (Mac & Linux) or `./build.ps1 virtualbox` (Windows).
    
    
## Troubleshooting:    
* To verify that building process completed successfully, ensure you are in `DetectionLabELK/Vagrant` directory and run `vagrant status`. The four machines (wef,dc,logger and win10) should be running. if one of the machines was not running, execute `vagrant reload <host>`. If you would like to pause the whole lab, execute `vagrant suspend` and resume it using `vagrant resume`.
* Deployment logs will be present in the `Vagrant` folder as `vagrant_up_<host>.log`


## Lab Access: 
* Navigate to https://192.168.38.105:8080/guacamole in a browser to access Guacamole. Default credentials are vagrant:vagrant.
* Navigate to https://192.168.38.105:5601 in a browser to access the Kibana dashboard on logger.
* Navigate to https://192.168.38.105:8412 in a browser to access the Fleet server on logger. Default credentials are admin:admin123#.
* Navigate to https://192.168.38.103 in a browser to access Microsoft ATA. Default credentials are wef\vagrant:vagrant.

**Support**: If you face any problem, please open a new [issue](https://github.com/cyberdefenders/DetectionLabELK/issues) and provide relevant log file.
