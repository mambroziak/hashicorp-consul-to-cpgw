#!/usr/bin/env/python

import json
import sys
import os
import requests
from requests.exceptions import HTTPError
import argparse
from argparse import RawTextHelpFormatter
from datetime import datetime
import random

OPTIONS = ''

# SSL Certificate Checking is disabled!
requests.packages.urllib3.disable_warnings()


def cp_login():
    cp_api_user = ''
    cp_api_pw = ''

    try:
        cp_api_user = os.environ['cp_api_user']
        cp_api_pw = os.environ['cp_api_pw']
        print('\nEnvironment variables found for Check Point API credentials.')
    except KeyError:
        print('\nError reading environment variables for Check Point API credentials.')
        exit(code=1)

    payload = {
        'user': cp_api_user,
        'password': cp_api_pw
    }

    resp = cp_http_request(url='/web_api/login', headers={'Content-Type': 'application/json'},
                           payload=payload, silent=False)
    resp = json.loads(resp.content)
    print(resp['sid'])
    return resp['sid']


def cp_publish(headers):
    print('\nPublishing session changes...')
    cp_http_request(url='/web_api/publish', headers=headers, payload={}, silent=False)


def cp_discard(headers):
    print('\nDiscarding session changes...')
    cp_http_request(url='/web_api/discard', headers=headers, payload={}, silent=False)


def process_intentions(headers):
    process_failures = 0
    process_successes = 0
    process_skips = 0
    consul_intentions = consul_get_intentions()
    print('\n' + json.dumps(consul_intentions, indent=2))

    print('No. of Consul intention records found: %s' % str(len(consul_intentions)))
    for c_intent in consul_intentions:
        print('\n----------------------------\nProcessing next Consul intention...\n----------------------------')
        new_rule_name = 'consul-' + c_intent['id'][0:12]
        access_layer = c_intent['access_layer']

        cp_access_layer_exists = cp_get_accesslayer_exists(headers, access_layer)
        if not cp_access_layer_exists:
            print('Check Point access layer not found: %s. Skipping intention...' % access_layer)
            process_failures += 1
            continue

        cp_access_rule_exists = cp_get_access_rule_exists(headers, new_rule_name, access_layer)
        if cp_access_rule_exists:
            process_skips += 1
            continue

        src_host_name = c_intent['source']['name'] + '.service.consul'
        dest_host_name = c_intent['destination']['name'] + '.service.consul'

        if OPTIONS.demo_mode:
            src_ip = '192.168.' + str(random.randrange(1, 254)) + '.' + str(random.randrange(1, 254))
            dest_ip = '10.1.' + str(random.randrange(1, 254)) + '.' + str(random.randrange(1, 254))
        else:
            src_ip = c_intent['source']['localServiceAddress']
            dest_ip = c_intent['destination']['localServiceAddress']

        add_hosts_payload = [{
            'name': src_host_name,
            'ip-address': src_ip
        },
            {
                'name': dest_host_name,
                'ip-address': dest_ip
            }]

        for host_payload in add_hosts_payload:

            print('\nProcessing host: %s' % host_payload['name'])
            cp_add_object_host(headers, host_payload)

        svc_object_id = cp_add_object_service(headers=headers, consul_id=c_intent['id'],
                                              dest_port=c_intent['destination']['localServicePort'])

        fw_action = ''
        fw_position = ''
        if c_intent['action'] == 'allow':
            fw_position = 'top'
            fw_action = 'Accept'
        elif c_intent['action'] == 'deny':
            fw_position = 'top'
            fw_action = 'Drop'

        print('\nProcessing access rule: %s/%s -> %s @ %s' % (fw_action, src_host_name, dest_host_name, access_layer))

        add_access_rule_payload = {
            'layer': access_layer,
            'position': fw_position,
            'name': new_rule_name,
            'source': src_host_name,
            'destination': dest_host_name,
            'service': svc_object_id,
            'action': fw_action
        }
        print('\n' + json.dumps(add_access_rule_payload, indent=2))
        access_rule_resp = cp_http_request(url='/web_api/add-access-rule', headers=headers,
                                           payload=add_access_rule_payload, silent=False)

        if access_rule_resp:
            process_successes += 1
        else:
            print('\nError inserting new rule.')
            process_failures += 1
            continue

    print('\nConsul-CheckPoint\nSync Status Report:\n  Successes: %s\n  Skips: %s\n  Failures: %s' % (
        process_successes, process_skips, process_failures))
    report = {'successes': process_successes, 'skips': process_skips, 'failures': process_failures}
    return report


def cp_add_object_host(headers, host_payload):
    query_payload = {'name': host_payload['name']}
    if OPTIONS.verbose:
        print(host_payload)

    resp = cp_http_request(url='/web_api/show-host', headers=headers, payload=query_payload,
                           silent=True)
    resp = json.loads(resp.content)

    if 'name' in resp.keys():
        print('Existing host object found.')
        return resp['name']
    else:
        print('\nCreating new host object...')
        cp_addhost_resp = cp_http_request(url='/web_api/add-host', headers=headers,
                                          payload=host_payload, silent=False)
        cp_addhost_resp = json.loads(cp_addhost_resp.content)
        return cp_addhost_resp['name']


def cp_add_object_service(headers, consul_id, dest_port):
    svc_object_id = ''
    offset = 0
    new_svcobjects = True
    cp_showservicestcp_resp = cp_http_request(url='/web_api/show-services-tcp', headers=headers,
                                              payload={'limit': 100, 'offset': offset, 'details-level': 'full'},
                                              silent=True)
    cp_showservicestcp_resp = json.loads(cp_showservicestcp_resp.content)
    while new_svcobjects:
        for svcobject in cp_showservicestcp_resp['objects']:
            if svcobject['port'] == dest_port:
                svc_object_id = svcobject['uid']
                print('\nExisting service object found: %s / %s' % (svcobject['name'], svcobject['uid']))
                break
        offset += 100
        cp_showservicestcp_resp = cp_http_request(url='/web_api/show-services-tcp',
                                                  headers=headers,
                                                  payload={'limit': 100, 'offset': offset, 'details-level': 'full'},
                                                  silent=True)
        cp_showservicestcp_resp = json.loads(cp_showservicestcp_resp.content)
        new_svcobjects = cp_showservicestcp_resp['objects']

    if svc_object_id == '':
        print('\nExisting service object not found. Creating one...')
        new_service_name = 'consul-' + consul_id[0:12]
        add_service_tcp_payload = {
            'name': new_service_name,
            'port': dest_port
        }
        print('\n' + json.dumps(add_service_tcp_payload, indent=2))
        cp_addservicetcp_resp = cp_http_request(url='/web_api/add-service-tcp', headers=headers,
                                                payload=add_service_tcp_payload, silent=False)
        cp_addservicetcp_resp = json.loads(cp_addservicetcp_resp.content)
        svc_object_id = cp_addservicetcp_resp['uid']

    return svc_object_id


def cp_get_accesslayer_exists(headers, access_layer_name):
    query_payload = {'name': access_layer_name}
    if OPTIONS.verbose:
        silent = False
        print('\nChecking if access layer exists:')
        print(query_payload)
    else:
        silent = True

    resp = cp_http_request(url='/web_api/show-access-layer', headers=headers, payload=query_payload,
                           silent=silent)
    resp = json.loads(resp.content)

    if 'code' not in resp and access_layer_name == resp['name']:
        print('\nExisting Check Point access layer found with name: %s' % access_layer_name)
        return True
    else:
        return False


def cp_get_access_rule_exists(headers, fw_rule_name, access_layer):
    query_payload = {'name': fw_rule_name, 'layer': access_layer}
    if OPTIONS.verbose:
        silent = False
        print('\nChecking if rule exists:')
        print(query_payload)
    else:
        silent = True

    resp = cp_http_request(url='/web_api/show-access-rule', headers=headers, payload=query_payload,
                           silent=silent)
    resp = json.loads(resp.content)

    if 'code' not in resp and fw_rule_name == resp['name']:
        print('\nExisting Check Point firewall access rule found with name: %s' % fw_rule_name)
        return True
    else:
        return False


def consul_get_intentions():
    c_intent_resp = consul_get_request(url='/v1/connect/intentions', silent=False)
    c_intent_resp = json.loads(c_intent_resp.content)
    if OPTIONS.verbose:
        print('\n' + json.dumps(c_intent_resp, indent=2))

    intentions = []
    for intention in c_intent_resp:
        print('\nID: %s\nSource: %s\nDestination: %s\nAction: %s' % (
            intention['ID'], intention['SourceName'], intention['DestinationName'], intention['Action']
        )
              )

        # More logic needed here to detect if a sidecar proxy is in use or not for the consul service
        c_src_svccat_resp = consul_get_request(
            url='/v1/catalog/service/' + intention['SourceName'] + '-sidecar-proxy', silent=True)
        c_src_svccat_resp = json.loads(c_src_svccat_resp.content)

        c_dest_svccat_resp = consul_get_request(
            url='/v1/catalog/service/' + intention['DestinationName'] + '-sidecar-proxy', silent=True)
        c_dest_svccat_resp = json.loads(c_dest_svccat_resp.content)

        if OPTIONS.verbose:
            print('\n' + json.dumps(c_src_svccat_resp, indent=2))
            print('\n' + json.dumps(c_dest_svccat_resp, indent=2))

        if OPTIONS.ignore_layers:
            access_layer = 'Network'
        elif 'check_point_access_layer' in intention['Meta']:
            # Read cosul intention metadata for Check Point Firewall layer value
            access_layer = intention['Meta']['check_point_access_layer']
        else:
            # Check Point Default layer
            # You may want to change this so that this rule fails instead of assuming the Network layer
            print('Missing check_point_access_layer in consul intention metadata. Setting layer to "Network" (Default)')
            access_layer = 'Network'

        # It is assumed that all consul source services use a side-car proxy
        intentions.append({
            'id': intention['ID'].replace('-', ''),
            'action': intention['Action'],
            'access_layer': access_layer,
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

    return intentions


def cp_http_request(url, headers, payload, silent):
    # silent = True/False

    resp = ''
    verify = False

    try:
        resp = requests.post('https://' + OPTIONS.cp_mgmt_ip + url, json=payload, headers=headers, verify=verify)
        resp.raise_for_status()
    except HTTPError as http_err:
        if not silent:
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
        resp = requests.get('http://' + OPTIONS.consul_socket + url, headers=headers)
        resp.raise_for_status()
    except HTTPError as http_err:
        if not silent:
            print('HTTP error occurred: %s' % http_err)
    except Exception as err:
        print('Other error occurred: %s' % err)
    else:
        if not silent:
            print('Success!')

    return resp


def main(argv=None):
    global OPTIONS

    # define argparse helper meta
    example_text = 'Example: \n %s --cp-mgmt-ip 3.4.5.6 --consul-socket 7.8.9.10:8500' % \
                   sys.argv[0]

    parser = argparse.ArgumentParser(
        epilog=example_text,
        formatter_class=RawTextHelpFormatter)
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    # Add arguments to argparse
    required.add_argument('--cp-mgmt-ip',
                          dest='cp_mgmt_ip',
                          help='Check Point Management Server IP (e.g. 10.10.1.254)',
                          required=True)
    required.add_argument('--consul-socket',
                          dest='consul_socket',
                          help='Consul socket address (e.g. 10.20.1.254:8500)',
                          required=True)
    optional.add_argument('--ignore-layers',
                          dest='ignore_layers',
                          default=False,
                          help='Consul intention tag "check_point_access_layer" ignored. Default layer: "Network"',
                          action='store_true')
    optional.add_argument('--demo-mode',
                          dest='demo_mode',
                          default=False,
                          help='Demo mode. Consul intention source/destination IPs autogenerated',
                          action='store_true')
    optional.add_argument('--dry-run',
                          dest='dry_run',
                          default=False,
                          help='Dry Run. Discard changes at the end.',
                          action='store_true')
    optional.add_argument('--verbose',
                          dest='verbose',
                          default=False,
                          help='Verbose output',
                          action='store_true')

    if len(sys.argv) == 1:
        parser.print_help()
        exit(code=1)

    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        parser.print_help()
        exit(code=1)

    OPTIONS = parser.parse_args(argv)
    if OPTIONS.cp_mgmt_ip and OPTIONS.consul_socket:
        print(
            '\n:: HashiCorp Consul to Check Point access control integration :: \nExecution time: %s \n' % str(datetime.now())
            )
    else:
        parser.print_help()
        exit(code=1)

    if OPTIONS.ignore_layers:
        print('\nIgnore layers flag enabled. Forcing access layer of Consul intentions to: "Network"')

    if OPTIONS.dry_run:
        print('\nDry run enabled.')

    if OPTIONS.demo_mode:
        print('\nDemo mode enabled: Consul intention source and destination IPs will be autogenerated.')

    # CP Login and get SID
    cp_sid = cp_login()
    print('sid: %s' % cp_sid)
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        'X-chkp-sid': cp_sid
    }

    # process intentions and insert access rules into Check Point appliance
    process_report = process_intentions(headers)

    if process_report['successes'] >= 1:
        print('\nConsul intentions and Check Point access rules have been synchronized.')
        if OPTIONS.dry_run:
            # Dry run, discard all posted changes in session.
            print('\nDry run enabled. Changes will not be saved.')
            cp_discard(headers)
        else:
            # Game on. Changes in session will be published.
            cp_publish(headers)
    else:
        print('\nNo new changes to publish. Review the status report.')
        cp_discard(headers)


if __name__ == "__main__":
    sys.exit(main())
