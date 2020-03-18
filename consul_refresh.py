#!/usr/bin/env python

import json
import sys
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError

consult_conn_addr = '127.0.0.1:8500'

def consul_get_request(url, silent): 
    # silent = True/False

    headers = {'content-type': 'application/json'}
    resp = ''
    try:
        resp = requests.get('http://' + consult_conn_addr + url, headers=headers)
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
    global consult_conn_addr
    c_intent_resp = consul_get_request(url='/v1/connect/intentions', silent=False)
    c_intent_resp = json.loads(c_intent_resp.content)
    #print('\n' + json.dumps(resp, indent=2))
    
    if c_intent_resp[0]['Action'] == 'allow':
        intent_src = c_intent_resp[0]['SourceName']
        intent_dest = c_intent_resp[0]['DestinationName']
        print('\nSrc: %s\nDest: %s' % (intent_src, intent_dest) )
    else:
        print('No Consul Intentions of Allow discovered. Program will exit.')
        sys.exit()
    
    c_src_agent_resp = consul_get_request(url='/v1/agent/service/' + intent_src + '-sidecar-proxy', silent=False)
    c_src_agent_resp = json.loads(c_src_agent_resp.content)
    
    fwr_src_svc_addr = c_src_agent_resp['Proxy']['LocalServiceAddress']
    fwr_src_svc_port = c_src_agent_resp['Proxy']['LocalServicePort']
    fwr_src_bind_port = c_src_agent_resp['Proxy']['Upstreams'][0]['LocalBindPort']
    #print('\n' + json.dumps(c_src_agent_resp, indent=2))
    print('\nSource Service Address: %s\nSource Local Service Port %s\nSource Proxy Bind Port %s' % (fwr_src_svc_addr, fwr_src_svc_port, fwr_src_bind_port) )
    
    c_dest_agent_resp = consul_get_request(url='/v1/agent/service/' + intent_dest + '-sidecar-proxy', silent=False)
    c_dest_agent_resp = json.loads(c_dest_agent_resp.content)
    fwr_dest_svc_addr = c_dest_agent_resp['Proxy']['LocalServiceAddress']
    fwr_dest_svc_port = c_dest_agent_resp['Proxy']['LocalServicePort']
    #print('\n' + json.dumps(c_dest_agent_resp, indent=2))
    print('\nDestination Service Address: %s\nDestination Service Port %s' % (fwr_dest_svc_addr, fwr_dest_svc_port) )  
        
if __name__ == "__main__":
    sys.exit(main())