# HashiCorp Consul to Check Point firewall integration
An automation script for Check Point Security Gateways to gather metrics via CP SmartEvent and send an aggregated payload to New Relic Insights.

>This project has been tested on CG GW R80.20.

## **Process Summary** 
The following explains what this tool does in sequence at a high level:
1. Read query parameters from user input and build query for SmartEvent
2. Build a single New Relic payload with all metrics.
3. Send the payload to New Relic Insights via API.
4. Script exits after single execution; expected usage is via cron.

## Requirements
* Expert mode access to Check Point OS (Gaia)
* Staging environment with Python v2.7.x 
* requests v2.22+

## Setup
#### Check Point Appliance Setup
>  Note: In order for SCP to function properly, a user with a 'bash' shell is necessary. Check Point recommends creating a dedicated user for these types of administrative tasks per SK95850. As a workaround one may change the admin users shell to /bin/bash temporarily as indicated below. 
1. SSH to Check Point appliance CLI as admin and set the shell to bash:
`set user admin shell /bin/bash`
2. Setup the appliance expert password and enter expert mode:
  ```bash
  set expert-password
  save config
  expert
```
3. You will return to the Check Point appliance in later steps.

#### [Optional] Prepare python virtual environment for export
Python libraries have already been exported for you as `site-packages.tar.gz` in this repo. If you'd like to build it on your own, then follow the instructions below.
1. Create a RHEL/CentOS instance to stage a virtual environment
2. Install python2, pip and virtualenv.
* `yum install python2 python2-pip python2-virtualenv -y`
3. Setup python virtual environment and dependencies
```bash
python2path=/usr/bin/python2.7 # Set to real python2 path if different
virtualenv -p $python2path cpgaia-pythonenv
source cpgaia-pythonenv/bin/activate
pip install requests
deactivate
rm -rf ./cpgaia-pythonenv/lib/python2.7/site-packages/Cryptodome/ # remove to avoid conflict
tar -czvf site-packages.tar.gz -C ./cpgaia-pythonenv/lib/python2.7/site-packages/ .
```

#### Upload Scripts, config file, and Python libraries to appliance
1. Using SCP, transfer `site-packages.tar.gz`, `cpsme_to_nr.py` and `timezone.conf` to the appliance home directory.
```bash
# Example deployment to Appliance: SCP the files to the appliance (SFTP not supported)
scp -i ~/mykey.pem ./site-packages.tar.gz admin@<appliance-ip>:/home/admin # Verify key path, tar path, and destination path
scp -i ~/mykey.pem ./cpsme_to_nr.py admin@<appliance-ip>:/home/admin
scp -i ~/mykey.pem ./timezone.conf admin@<appliance-ip>:/home/admin
```
### Import/deploy on Check Point Appliance 
1. Login to Check Point appliance CLI as admin in expert-mode.
2. Change to the home directory `cd ~/`
3. Python PIP is not installed on Check Point appliances. Untar the Python libraries loaded in the previous step.
```bash
tar -xvf ./site-packages.tar.gz -C $FWDIR/Python/lib/python2.7/site-packages
```
4. Move the script files to `$FWDIR/scripts/cpsme_to_nr`
```bash
mkdir $FWDIR/scripts/cpsme_to_nr
mv ./cpsme_to_nr.py $FWDIR/scripts/cpsme_to_nr
mv ./timezone.conf $FWDIR/scripts/timezone.conf
cd $FWDIR/scripts/cpsme_to_nr
```
#### Customizing the timezone.conf file
The `timezone.conf` file contains a single line to specify the local timezone. The expected format is [TZ database name](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones).

## Operation
To run the script, review the arguments of the script and the syntax.

### Arguments 
Below are the global and mode-specific arguments.

| Argument             | Description                                                  | Default value |
|----------------------|--------------------------------------------------------------|---------------|
| `--account`          | New Relic account number                                     | |
| `--key`              | New Relic Insights insert key                                | |
| `--minutes`          | Time (in minutes) from date/time (now) to query event history| |	
| `--product`          | Query filter Product. See below for valid product values | `all` |		
| `--verbose`          | Verbose output                                               | `False` |	

#### Product argument values
Only one product may be specified at a time. Otherwise, use the `all` value.

| Product Value  | Product Description |
|----------------|---------------------|
| `all`          | All products |
| `ac`           | Application Control |
| `uf`           | URL Filtering |
| `ab`           | Anti-Bot |
| `av`           | Anti-Virus |
| `ips`          | IPS |
| `te`           | Threat Emulation |
| `tx`           | Threat Extraction |

### How to run:
```bash
# Syntax
python $FWDIR/scripts/cpsme-to-nr/cpsme_to_nr.py --account 1234567 --key 12345678Z-2jAnRQlUHgjjKE12345678 --minutes 1440 --product all --verbose
```
