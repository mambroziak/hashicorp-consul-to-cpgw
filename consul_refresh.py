#!/usr/bin/env/python3

import json
import sys
import requests
import os
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError

cp_conn_addr = '3.227.98.36'
consul_conn_addr = '127.0.0.1:8500'

def poll_consul():
    c_intent_resp = consul_get_request(url='/v1/connect/intentions', silent=False)
    c_intent_resp = json.loads(c_intent_resp.content)
    #print('\n' + json.dumps(resp, indent=2))
    
    if c_intent_resp[0]['Action'] == 'allow':
        intent_src_name = c_intent_resp[0]['SourceName']
        intent_dest_name = c_intent_resp[0]['DestinationName']
        print('\nSource: %s\nDestination: %s' % (intent_src_name, intent_dest_name) )
    else:
        print('No Consul Intentions of Allow discovered. Program will exit.')
        sys.exit()
    
    c_src_agent_resp = consul_get_request(url='/v1/catalog/service/' + intent_src_name + '-sidecar-proxy', silent=True)
    c_src_agent_resp = json.loads(c_src_agent_resp.content)
    #print('\n' + json.dumps(c_src_agent_resp, indent=2))

    c_dest_agent_resp = consul_get_request(url='/v1/catalog/service/' + intent_dest_name + '-sidecar-proxy', silent=True)
    c_dest_agent_resp = json.loads(c_dest_agent_resp.content)
    #print('\n' + json.dumps(c_dest_agent_resp, indent=2))
    
    result = {
      'source': {
        'name': intent_src_name,
        'localServiceAddress': c_src_agent_resp[0]['ServiceProxy']['LocalServiceAddress'],
        'localServicePort': c_src_agent_resp[0]['ServiceProxy']['LocalServicePort'],
        'localBindPort': c_src_agent_resp[0]['ServiceProxy']['Upstreams'][0]['LocalBindPort'] 
        },
      'destination': {
        'name': intent_dest_name,
        'localServiceAddress': c_dest_agent_resp[0]['ServiceProxy']['LocalServiceAddress'],
        'localServicePort': c_dest_agent_resp[0]['ServiceProxy']['LocalServicePort']
      }
    }
    return result

def cp_http_request(request_type, url, headers, payload, silent): 

    # request_type = post/delete/get
    request_type = request_type.lower()
    # silent = True/False

    resp = ''
    verify = False
    try:
        if request_type.lower() == 'post':
            resp = requests.post('https://' + cp_conn_addr + url, json=payload, headers=headers, verify=verify)
        elif request_type.lower() == 'delete':
            resp = requests.delete('https://' + cp_conn_addr + url, json=payload, headers=headers, verify=verify)
        elif request_type.lower() == 'get':
            resp = requests.get('https://' + cp_conn_addr + url, json=payload, headers=headers, verify=verify)
        else:
            print('Request type not supported.')
            return False
        
        resp.raise_for_status()
    except HTTPError as http_err:
        print('HTTP error occurred: %s' % http_err) 
    except Exception as err:
        print('Other error occurred: %s' % err)   
    else:
        if not silent:
            print('Success!')
    
    return resp

def consul_get_request(url, silent): 
    # silent = True/False

    headers = {'content-type': 'application/json'}
    resp = ''
    try:
        resp = requests.get('http://' + consul_conn_addr + url, headers=headers)
        resp.raise_for_status()
    except HTTPError as http_err:
        print('HTTP error occurred: %s' % http_err) 
    except Exception as err:
        print('Other error occurred: %s' % err)  
    else:
        if not silent:
            print('Success!')
    
    return resp

def main(argv=None):
    global cp_conn_addr, consul_conn_addr
    
    pollres = poll_consul()
    print('\n' + json.dumps(pollres, indent=2))

    try:
        cp_api_user = os.environ['cp_api_user']
        cp_api_pw = os.environ['cp_api_pw']
        print('Environment variables found for Check Point API credentials.')
    except KeyError: 
        print('Error reading environment variables for Check Point API credentials.')
        os._exit(1)
    
    login_payload = {
      'user': cp_api_user,
      'password':cp_api_pw
    }
    
    cp_auth_resp = cp_http_request(request_type='post', url='/web_api/login', headers={'Content-Type': 'application/json'}, payload=login_payload, silent=False)
    cp_auth_resp = json.loads(cp_auth_resp.content)
    cp_api_sid = cp_auth_resp['sid']
    print(cp_api_sid)
    
    add_host_payload = {
      'name' : pollres['source']['name'],
      'ip-address' : pollres['source']['localServiceAddress']
    }
    
    cp_addhost_resp = cp_http_request(request_type='post', url='/web_api/add-host', headers={'Content-Type': 'application/json', 'X-chkp-sid': cp_api_sid}, payload=add_host_payload, silent=False)
    
if __name__ == "__main__":
    sys.exit(main())