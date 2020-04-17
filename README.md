# HashiCorp Consul to Check Point access control integration
An automation script for Check Point Security Gateways to poll Consul Intentions via REST API and transform intentions into access control rules.

>This project has been tested on CG GW R80.20.

## **Process Summary** 
The following explains what this tool does in sequence at a high level:
1. Poll Consul intentions and metadata
2. Open an API session with Check Point appliance management server.
3. Validate existance of services, hosts and layers for each intention and create an access control rule.
4. Upon validation, publish session all changes. Otherwise, discard session.

## Requirements
* Expert mode access to Check Point OS (Gaia)
* Staging environment with Python v2.7.x (If building the package yourself)
* Python requests v2.22+
* Execution Environment Variables: 
  * `cp_api_user`
  * `cp_api_pw`

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
1. Install python2, pip and virtualenv.
* `yum install python2 python2-pip python2-virtualenv -y`
3. Setup python virtual environment and dependencies
```bash
python2path=/usr/bin/python2.7 # Set to real python2 path if different
virtualenv -p $python2path cpgaia-pythonenv
source cpgaia-pythonenv/bin/activate
pip install requests==2.22
deactivate
rm -rf ./cpgaia-pythonenv/lib/python2.7/site-packages/Cryptodome/ # remove to avoid conflict
tar -czvf site-packages.tar.gz -C ./cpgaia-pythonenv/lib/python2.7/site-packages/ .
```

#### Upload Scripts, config file, and Python libraries to Check Point appliance
1. Using SCP, transfer `site-packages.tar.gz`, `consul_to_cpgw.py` to the appliance home directory.
```bash
# Example deployment to Appliance: SCP the files to the appliance (SFTP not supported)
scp -i ~/mykey.pem ./site-packages.tar.gz admin@<appliance-ip>:/home/admin # Verify key path, tar path, and destination path
scp -i ~/mykey.pem ./consul_to_cpgw.py admin@<appliance-ip>:/home/admin
```
#### Import/deploy on Check Point appliance 
1. Login to Check Point appliance CLI as admin in expert-mode.
1. Change to the home directory `cd ~/`
1. Python PIP is not installed on Check Point appliances. Untar the Python libraries loaded in the previous step.
```bash
tar -xvf ./site-packages.tar.gz -C $FWDIR/Python/lib/python2.7/site-packages
```
4. Move the script files to `$FWDIR/scripts/consul_to_cpgw`
```bash
mkdir $FWDIR/scripts/consul_to_cpgw
mv ./cpsme_to_nr.py $FWDIR/scripts/consul_to_cpgw
cd $FWDIR/scripts/consul_to_cpgw
```
_Enable Check Point R80 API_
If not already enabled, the R80 will need to be enabled using the CLI.
```bash
mgmt_cli -r true --domain MDS set api-settings accepted-api-calls-from "All IP addresses"
api restart
```
_Create an API user_
On the management server, create a username and password for API access with **Super User** access. These credentials will be used as environment variables during script execution.

### Setup and Run Consul Services for Demo (optional)
1. Login to the Consul catalog server (https://learn.hashicorp.com/consul)
2. Copy example Consul services from repo located in `examples/consul.d/` to Consul config directory (e.g. `/etc/consul.d`)
3. Run Consul in the background: `nohup  consul agent -dev -enable-script-checks -config-dir=/etc/consul.d &`
4. Register some intentions with the required metadata
```bash
consul intention create -meta check_point_access_layer='<layer-name>' -allow web1 socat1
consul intention create -meta check_point_access_layer='<layer-name>' -deny web2 socat2
consul intention create -meta check_point_access_layer='<layer-name>' -allow web3 socat3
consul intention create -meta check_point_access_layer='<layer-name>' -allow web4 socat4
```
> Note: Intentions may be purged when the Consul service is stopped.

## Operation
To run the script, review the arguments of the script and the syntax.
> Note: If you receive 400 errors during script execution, ensure that there are no stale API sessions with unpublished changes on the management server.

### Arguments 
Below are required* and optional arguments.

| Argument              | Description                                                  | Default value |
|-----------------------|--------------------------------------------------------------|---------------|
| `--cp-mgmt-ip`*       | Check Point Management Server IP (e.g. 10.10.1.254)          | |
| `--consul-socket`*    | Consul socket address (e.g. 10.20.1.254:8500)                | |
| `--ignore-layers`     | Consul intention tag "check_point_access_layer" ignored. Default layer: "Network"| `False` |	
| `--demo-mode`         | Demo mode. Consul intention source/destination IPs autogenerated | `False` |		
| `--dry-run`           | Dry Run. Discard changes at the end of process.              | `False` |
| `--verbose`           | Verbose output                                               | `False` |
> Note: Access Layers must be predefined in Check Point access control. If a layer is not found it will default to "Network", the Check Point default layer name.


### How to run:
```bash
# Set environment variables
export cp_api_user='<API-user>'
export cp_api_pw='<password>'
# Execution Syntax
python consul_to_cpgw.py --cp-mgmt-ip 10.10.1.254 --consul-socket 10.20.1.254:8500
python consul_to_cpgw.py --cp-mgmt-ip 10.10.1.254 --consul-socket 10.20.1.254:8500 --demo-mode --dry-run
```
