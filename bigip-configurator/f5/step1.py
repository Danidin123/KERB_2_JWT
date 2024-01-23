# step1.py

from f5.bigip import ManagementRoot
import requests, json, urllib3, re


BIGIP_BASE_ADDRESS = "cd95ca01-6ec6-480c-99b9-4d37b1329e46.access.udf.f5.com"
DEBUG = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def bigip_login(username, password):
    session = requests.session()
    session.verify = False
    get_biqip_token = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}', token=True, debug=True)
    bigip_token = get_biqip_token.icrs.token
    url = f"https://{BIGIP_BASE_ADDRESS}/tmui/logmein.html?"
    headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'content-type': 'application/x-www-form-urlencoded',
            'Referer': f"https://{BIGIP_BASE_ADDRESS}/tmui/login.jsp"
    }
    data = {'username': f'{username}', 'passwd': f'{password}'}
    response = session.post(url, headers=headers, data=data, verify=False)
    formatted_cookies = '; '.join([f"{cookie.name}={cookie.value}" for cookie in response.cookies])
    return bigip_token, formatted_cookies


def bigip_post(endpoint, data, bigip_token):
    session = requests.session()
    session.verify = False
    headers = {
            'accept': 'application/json',
            'content-type': 'application/json',
            'X-F5-Auth-Token': f'{bigip_token}'
    }
    response = session.post(url=f"https://{BIGIP_BASE_ADDRESS}{endpoint}", headers=headers, data=json.dumps(data))
    if DEBUG:
        print(f"Full URL:    {BIGIP_BASE_ADDRESS}{endpoint}")
        print(response.text)
    return response.status_code


def get_pool_member(username, password):
    get_bigip_token = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}')
    pool_members = get_bigip_token.tm.ltm.nodes.get_collection()
    pool_member_ips =[pool_member.address for pool_member in pool_members]
    return pool_member_ips


def check_pool_member(username, password, backend_server):
    pool_member_ips = get_pool_member(username, password)
    if backend_server in pool_member_ips:
        return True
    else:
        return False


def pool_name(username, password):
    get_bigip_token = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}', token=True, debug=True)
    pools = get_bigip_token.tm.ltm.pools.get_collection()
    pool_names = [pool.name for pool in pools]
    return pool_names


def create_audience(audience, username, password):
    mgmt = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}')
    tmsh_create_audience = """ tmsh modify apm oauth jwt-config sharon_audience audience add  {{ "{audience}" }}  """
    audience = tmsh_create_audience.format(audience=audience)
    mgmt.tm.util.bash.exec_cmd('run', utilCmdArgs='-c "{}"'.format(audience))
    mgmt.tm.util.bash.exec_cmd('run', utilCmdArgs='-c "tmsh save sys config"')
    print("audience was created")


def create_pre_request_policy(service_name, bigip_token, formatted_cookies):
    session = requests.session()
    session.verify = False
    headers = {'accept': '*/*',
               'content-type': 'text/plain;charset=UTF-8',
               'Referer': f'https://{BIGIP_BASE_ADDRESS}/sam/admin/vpe2/public/php/vpe.php?r[accessPolicyName]=/Common/{service_name}_prp',
               'Cookie': f'{formatted_cookies}, F5_CURRENT_PARTITION=Common;'
               }
    endpoint1 = "/sam/admin/vpe2/public/php/server.php?nocache=1028768325"
    payload1 = f"<message><dialogueType>addItemDialogue</dialogueType><command>load</command><accessPolicyName>/Common/{service_name}_prp</accessPolicyName><status>ok</status><messageId>0</messageId><messageBody><policyName>/Common/{service_name}_prp</policyName></messageBody></message>"
    try:
        response1 = session.post(url=f"https://{BIGIP_BASE_ADDRESS}{endpoint1}", headers=headers, data=payload1)
        pattern = r'<messageId>(.*?)</messageId>'
        match = re.search(pattern, response1.text)
        message_id = match.group(1)
        if "ok" not in response1.text:
            raise Exception(response1.text)
    except Exception as e:
        print(f"Error creating per-request-policy state_1: {e}")

    endpoint2 = "/sam/admin/vpe2/public/php/server.php?nocache=1328568325"
    payload2 = f"<message><dialogueType>addItemDialogue</dialogueType><command>save</command><accessPolicyName>/Common/{service_name}_prp</accessPolicyName><status>ok</status><messageId>{message_id}</messageId><messageBody><where><policyName>/Common/{service_name}_prp</policyName><itemName>/Common/{service_name}_prp_mac_{service_name}_prp_auth</itemName><ruleIndex>0</ruleIndex></where><what><listName>general</listName><templateName>sso_configuration_select</templateName></what></messageBody></message>"
    try:
        response2 = session.post(url=f"https://{BIGIP_BASE_ADDRESS}{endpoint2}", headers=headers, data=payload2)
        pattern = r'<messageId>(.*?)</messageId>'
        match = re.search(pattern, response2.text)
        message_id = match.group(1)
        if "ok" not in response2.text:
            raise Exception(response2.text)
    except Exception as e:
        print(f"Error creating per-request-policy state_2: {e}")

    endpoint3 = "/sam/admin/vpe2/public/php/server.php?nocache=9349578813"
    payload3 = f'<message><dialogueType>editActionDialogue</dialogueType><command>load</command><accessPolicyName>/Common/{service_name}_prp</accessPolicyName><status>ok</status><messageId>0</messageId><messageBody><actionName>/Common/{service_name}_prp_act_sso_configuration_select</actionName></messageBody></message>'
    try:
        response3 = session.post(url=f"https://{BIGIP_BASE_ADDRESS}{endpoint3}", headers=headers, data=payload3)
        pattern = r'<messageId>(.*?)</messageId>'
        match = re.search(pattern, response3.text)
        message_id = match.group(1)
        if "ok" not in response3.text:
            raise Exception(response3.text)
    except Exception as e:
        print(f"Error creating per-request-policy state_3: {e}")

    endpoint4 = "/sam/admin/vpe2/public/php/server.php?nocache=9349558815"
    payload4 = f"""<?xml version="1.0" encoding="UTF-8"?><message><dialogueType>editActionDialogue</dialogueType><command>save</command><accessPolicyName>/Common/{service_name}_prp</accessPolicyName><status>ok</status><messageId>{message_id}</messageId><messageBody><action><caption>SSO Configuration Select</caption><actionName>/Common/{service_name}_prp_act_sso_configuration_select</actionName><agents><agent><name>/Common/{service_name}_prp_act_sso_configuration_select_ag</name><type>agent_sso_configuration_select</type><subtype></subtype><data><object id="agent_sso_configuration_select"><variable id="sso_config_name" value="/Common/keeb_sso_sharon"/></object></data><data2>\n<e type=\'original\'></e>\n<e type=\'current\'></e>\n</data2>\n</agent></agents><rules><rule><type>fallback</type><status>normal</status><initalIndex>0</initalIndex><index>0</index><caption>fallback</caption><expression></expression></rule></rules></action></messageBody></message>"""
    try:
        response4 = session.post(url=f"https://{BIGIP_BASE_ADDRESS}{endpoint4}", headers=headers, data=payload4)
        if "ok" not in response4.text:
            raise Exception(response4.text)
    except Exception as e:
        print(f"Error creating per-request-policy state_4: {e}")

    endpoint5 = "/sam/admin/vpe2/public/php/server.php?nocache=9348558813"
    payload5 = f'<message><dialogueType>editActionDialogue</dialogueType><command>load</command><accessPolicyName>/Common/{service_name}_prp_auth</accessPolicyName><status>ok</status><messageId>0</messageId><messageBody><actionName>/Common/{service_name}_prp_auth_act_oauth_scope_subsession</actionName></messageBody></message>'
    try:
        response5 = session.post(url=f"https://{BIGIP_BASE_ADDRESS}{endpoint5}", headers=headers, data=payload5)
        pattern = r'<messageId>(.*?)</messageId>'
        match = re.search(pattern, response5.text)
        message_id = match.group(1)
        if "ok" not in response5.text:
            raise Exception(response5.text)
    except Exception as e:
        print(f"Error creating per-request-policy state_5: {e}")

    endpoint6 = "/sam/admin/vpe2/public/php/server.php?nocache=9348558813"
    payload6 = f"""<?xml version="1.0" encoding="UTF-8"?><message><dialogueType>editActionDialogue</dialogueType><command>save</command><accessPolicyName>/Common/{service_name}_prp_auth</accessPolicyName><status>ok</status><messageId>{message_id}</messageId><messageBody><action><caption>OAuth Scope</caption><actionName>/Common/{service_name}_prp_auth_act_oauth_scope_subsession</actionName><agents><agent><name>/Common/{service_name}_prp_auth_act_oauth_scope_subsession_ag</name><type>agent_aaa_oauth</type><subtype></subtype><data><object id="agent_aaa_oauth"><variable id="type" value="1"/><variable id="token_validation_mode" value="0"/><variable id="using_dynamic_server" value="0"/><variable id="server" value="/Common/oauth_server"/><variable id="dynamicserver" value=""/><variable id="oauth_jwt_provider_list" value=""/><variable id="grant_type" value="0"/><variable id="openid_connect" value="0"/><variable id="openid_flow_type" value="0"/><variable id="openid_hybrid_response_type" value="0"/><variable id="request_auth_redirect" value=""/><variable id="request_token" value=""/><variable id="request_refresh_token" value=""/><variable id="request_revoke_token" value=""/><variable id="request_validate_token" value="/Common/F5ScopesRequest"/><variable id="request_openid_userinfo" value="/Common/F5UserinfoRequest"/><variable id="redirection_uri" value="https://%{{session.server.network.name}}/oauth/client/redirect"/><variable id="response" value=""/><variable id="scope" value=""/></object><vector id="oauth_scope_request" join="1"/></data><data2>\n<e type=\'original\'></e>\n<e type=\'current\'></e>\n</data2>\n</agent></agents><rules><rule><type>normal</type><status>normal</status><initalIndex>0</initalIndex><index>0</index><caption>Successful</caption><expression>expr%20%7B%5Bmcget%20%7Bsubsession.oauth.scope.last.authresult%7D%5D%20%3D%3D%201%7D</expression></rule><rule><type>fallback</type><status>normal</status><initalIndex>1</initalIndex><index>1</index><caption>fallback</caption><expression></expression></rule></rules></action></messageBody></message>"""
    try:
        response6 = session.post(url=f"https://{BIGIP_BASE_ADDRESS}{endpoint6}", headers=headers, data=payload6)
        if "ok" not in response6.text:
            raise Exception(response6.text)
        else:
            print("created a new pre-request-policy")
    except Exception as e:
        print(f"Error creating per-request-policy state_6: {e}")


def create_api_protection_profile(service_name, backend_address, bigip_token):
    endpoint = "/mgmt/tm/apiprotection/api-protection-profile"
    payload1 = {
        "name": f"/Common/{service_name}",
        "isNew": "true",
        "profileProperties": {
            "dnsMode": "ipv4-only",
            "usePool": "false",
            "authorizationSettings": ["oauth2"]
        },
        "partition": "Common"
    }
    payload2 = {
        "name": f"/Common/{service_name}",
        "isNew": "false",
        "profileProperties": {
            "defaultServer": "none",
            "dnsMode": "ipv4-only",
            "dnsResolver": "/Common/f5-aws-dns"
        },
        "paths": [],
        "servers": [
            {
                "name": f"/Common/{service_name}",
                "operation": "CREATE",
                "url": f"http://{backend_address}",
                "serversslProfile": "none"
            }
        ],
        "partition": "Common"
    }
    payload3 = {
        "name": f"/Common/{service_name}",
        "isNew": "false",
        "profileProperties": {
            "defaultServer": "none",
            "dnsMode": "ipv4-only",
            "dnsResolver": "/Common/f5-aws-dns"
        },
        "paths": [
            {
                "operation": "CREATE",
                "uri": "/",
                "method": "GET",
                "active": "true",
                "server": f"/Common/{service_name}"
            },
            {
                "operation": "CREATE",
                "uri": "/",
                "method": "POST",
                "active": "true",
                "server": f"/Common/{service_name}"
            }
        ],
        "servers": [],
        "partition": "Common"
    }
    bigip_post(endpoint, payload1, bigip_token)
    bigip_post(endpoint, payload2, bigip_token)  # create the server in the path tab
    bigip_post(endpoint, payload3, bigip_token)  # create the paths in the path tab
    print("created a new API protection profile")


def node_creator(backend_address, username, password):
    mgmt = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}')
    node_exist = check_pool_member(username, password, backend_address)
    print("Does the node existing:", node_exist)
    if node_exist is False:  # if the node NOT exist, create the node
        try:
            mgmt.tm.ltm.nodes.node.create(partition="Common", name=f"node_{backend_address}", address=f"{backend_address}")
            print("Node creation successful!")
        except Exception as e:
            print(f"Error creating node: {e}")
    else:
        print(f"The node {backend_address} already exist.")


def pool_creator(service_name, username, password):
    mgmt = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}')
    try:
        mgmt.tm.ltm.pools.pool.create(name=f"{service_name}_pool")
        print("Pool creation successful!")
    except Exception as e:
        print(f"Error creating pool: {e}")


def pool_members_assignment(service_name, backend_address, bigip_token, username, password):
    mgmt = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}')
    session = requests.session()
    session.verify = False
    member_port = '80'
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
        'X-F5-Auth-Token': f'{bigip_token}'
    }
    get_nodes_list = f'https://{BIGIP_BASE_ADDRESS}/mgmt/tm/ltm/node'  # return nodes list
    get_nodes_list = session.get(get_nodes_list, headers=headers)
    nodes_list = get_nodes_list.json()
    node_name = [y['name'] for y in nodes_list['items'] if y.get('address') == f'{backend_address}']
    node_name = node_name[0]
    try:
        pool = mgmt.tm.ltm.pools.pool.load(name=f"{service_name}_pool")
        pool.members_s.members.create(partition='Common', name=f"{node_name}" + ":" + member_port)
        print("Node assigned successfully to pool!")
    except Exception as e:
        print(f"Error assigned note to pool: {e}")


def check_if_vs_exist(backend_address, service_name, username, password):
    mgmt = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}')
    exist_vs = mgmt.tm.ltm.virtuals.get_collection()
    for vs in exist_vs:
        ip_pattern = re.compile(r'/Common/(\d+\.\d+\.\d+\.\d+):\d+')
        matches_vs = ip_pattern.findall(vs.destination)
        if vs.name:
            if vs.name == f"vs_{service_name}":
                print("vs name already exist")
                return True
        if matches_vs:
            ip_address = matches_vs[0]
            if ip_address == backend_address:
                print("vs IP already exist")
                return True


def vs_creator(service_name, virtual_address, username, password):
    mgmt = ManagementRoot(f'{BIGIP_BASE_ADDRESS}', f'{username}', f'{password}')
    params = {
            "name": f"vs_{service_name}",
            "destination": "{}:{}".format(f"{virtual_address}", str(80)),
            "mask": "255.255.255.255",
            "description": "KERB -> JWT",
            "pool": f"{service_name}_pool",
            "partition": "Common",
            "sourceAddressTranslation": {"type": "automap"},
            "profilesReference": {
                "isSubcollection": True,
                "items": [
                    {
                        "kind": "tm:ltm:virtual:profiles:profilesstate",
                        "name": "http",
                        "partition": "Common",
                        "fullPath": "/Common/http"
                    },
                    {
                        "kind": "tm:ltm:virtual:profiles:profilesstate",
                        "name": f"{service_name}",
                        "partition": "Common",
                        "fullPath": f"/Common/{service_name}"
                    }
                ]
            }
        }
    try:
        mgmt.tm.ltm.virtuals.virtual.create(**params)
        print("Virtual server creation successful!")
    except Exception as e:
        print(f"Error creating virtual server: {e}")
