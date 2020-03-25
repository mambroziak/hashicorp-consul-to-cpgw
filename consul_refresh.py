#!/usr/bin/env/python3

import json
import sys
import requests
import os
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError

cp_conn_addr = '3.227.98.36'
consul_conn_addr = '127.0.0.1:8500'

# SSL Certificate Checking is disabled!
requests.packages.urllib3.disable_warnings()

def poll_consul():
    c_intent_resp = consul_get_request(url='/v1/connect/intentions', silent=False)
    c_intent_resp = json.loads(c_intent_resp.content)
    #print('\n' + json.dumps(resp, indent=2))

    all_intentions = []
    for intention in c_intent_resp:
        print('\nID: %s\nSource: %s\nDestination: %s\nAction: %s' % (intention['ID'], intention['SourceName'], intention['DestinationName'], intention['Action']) )
        
        c_src_svccat_resp = consul_get_request(url='/v1/catalog/service/' + intention['SourceName'] + '-sidecar-proxy', silent=True)
        c_src_svccat_resp = json.loads(c_src_svccat_resp.content)
        #print('\n' + json.dumps(c_src_svccat_resp, indent=2))

        c_dest_svccat_resp = consul_get_request(url='/v1/catalog/service/' + intention['DestinationName'] + '-sidecar-proxy', silent=True)
        c_dest_svccat_resp = json.loads(c_dest_svccat_resp.content)
        #print('\n' + json.dumps(c_dest_svccat_resp, indent=2))
    
        all_intentions.append({
          'id': intention['ID'].replace('-',''),
          'action': intention['Action'],
          'source': {
            'name': intention['SourceName'],
            'localServiceAddress': c_src_svccat_resp[0]['ServiceProxy']['LocalServiceAddress'],
            'localServicePort': str(c_src_svccat_resp[0]['ServiceProxy']['LocalServicePort']),
            'localBindPort': str(c_src_svccat_resp[0]['ServiceProxy']['Upstreams'][0]['LocalBindPort'])
            },
          'destination': {
            'name': intention['DestinationName'],
            'localServiceAddress': c_dest_svccat_resp[0]['ServiceProxy']['LocalServiceAddress'],
            'localServicePort': str(c_dest_svccat_resp[0]['ServiceProxy']['LocalServicePort'])
          }
        })
    
    return all_intentions

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
    
    consul_intentions = poll_consul()
    print('\n' + json.dumps(consul_intentions, indent=2))

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
    
    cp_auth_resp = cp_http_request(request_type='POST', url='/web_api/login', headers={'Content-Type': 'application/json'}, payload=login_payload, silent=False)
    cp_auth_resp = json.loads(cp_auth_resp.content)
    cp_api_sid = cp_auth_resp['sid']
    print(cp_api_sid)
    
    headers = {
      'Content-Type': "application/json",
      'Cache-Control': "no-cache",
      'X-chkp-sid': cp_auth_resp['sid']
    }
    
    for c_intent in consul_intentions:
        src_host_name = c_intent['source']['name'] + '.service.consul'
        dest_host_name = c_intent['destination']['name'] + '.service.consul'
        add_hosts_payload = [{
          'name' : src_host_name,
          'ip-address' : '192.168.5.5'
          #'ip-address' : c_intent['source']['localServiceAddress']
        },
        {
          'name': dest_host_name,
          'ip-address' : '10.1.10.11'
          #'ip-address' : c_intent['destination']['localServiceAddress']
        }]
        print(add_hosts_payload)
        for host_payload in add_hosts_payload:
            cp_addhost_resp = cp_http_request(request_type='POST', url='/web_api/add-host', headers=headers, payload=host_payload, silent=False)


        
        svc_object_id = ''
        offset = 0
        new_svcobjects = True
        cp_showservicestcp_resp = cp_http_request(request_type='POST', url='/web_api/show-services-tcp', headers=headers, payload={'limit': 100, 'offset': offset, 'details-level': 'full'}, silent=True)
        cp_showservicestcp_resp = json.loads(cp_showservicestcp_resp.content)
        while new_svcobjects:
            for svcobject in cp_showservicestcp_resp['objects']:
                #print(svcobject['port'], svcobject['name'], svcobject['uid'])
                if svcobject['port'] == c_intent['destination']['localServicePort']:
                    svc_object_id = svcobject['uid']
                    print('\nExisting service object found: %s %s' % (svcobject['name'], svcobject['uid']))
                    break
            offset += 100
            cp_showservicestcp_resp = cp_http_request(request_type='POST', url='/web_api/show-services-tcp', headers=headers, payload={'limit': 100, 'offset': offset, 'details-level': 'full'}, silent=True)
            cp_showservicestcp_resp = json.loads(cp_showservicestcp_resp.content)
            new_svcobjects = cp_showservicestcp_resp['objects']

        if svc_object_id == '':
            print('\nExisting service object not found. Creating one...')
            add_service_tcp_payload = {
              'name': c_intent['id'],
              'port': str(c_intent['destination']['localServicePort'])
            }
            print('\n' + json.dumps(add_service_tcp_payload, indent=2))
            cp_addservicetcp_resp = cp_http_request(request_type='POST', url='/web_api/add-service-tcp', headers=headers, payload=add_service_tcp_payload, silent=False)
            cp_addservicetcp_resp = json.loads(cp_addservicetcp_resp.content)
            svc_object_id = cp_addservicetcp_resp['uid']

        if c_intent['action'] == 'allow':
            fw_action = 'Accept'
            fw_position = 'top'
        elif c_intent['action'] == 'deny':
            fw_position = 'bottom'
            fw_action = 'Drop'
            
        add_access_rule_payload = {
          'layer': 'Network',
          'position': fw_position,
          'name': c_intent['id'],
          'source': src_host_name,
          'destination': dest_host_name,
          'service': svc_object_id,
          'action': fw_action
        }
        print('\n' + json.dumps(add_access_rule_payload, indent=2))
        cp_addaccessrule_resp = cp_http_request(request_type='POST', url='/web_api/add-access-rule', headers=headers, payload=add_access_rule_payload, silent=False)
    
    show_hosts_payload = {
      'limit' : 50,
      'offset' : 0,
      'details-level' : 'standard'
    }
    
    #cp_showhosts_resp = cp_http_request(request_type='POST', url='/web_api/show-hosts', headers=headers, payload=show_hosts_payload, silent=False)
    print('Publish...')
    cp_publish_resp = cp_http_request(request_type='POST', url='/web_api/publish', headers=headers, payload={}, silent=False)
    
if __name__ == "__main__":
    sys.exit(main())