# /// script
# requires-python = ">=3.11"
# dependencies = ["playwright==1.64.0"]
# ///
"""Browser OAuth and live account setup regression with synthetic credentials.

Run after cargo build: uv run scripts/test-oauth-browser.py --browser PATH
No real provider, mailbox, or user browser profile is accessed.
"""
import argparse, base64, hashlib, http.client, http.server, json, os, tempfile
from pathlib import Path
import socket, subprocess, threading, time, urllib.parse, urllib.request
from playwright.sync_api import sync_playwright

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--browser',required=True,type=Path)
parser.add_argument('--server-binary',type=Path,default=root/'target/debug'/('mail-bridge-rust.exe' if os.name=='nt' else 'mail-bridge-rust'))
args=parser.parse_args()
workroot=root/'.research/browser-consent-tests'
workroot.mkdir(parents=True,exist_ok=True)
work=Path(tempfile.mkdtemp(prefix='case-',dir=workroot))
temporary=work/'tmp'
temporary.mkdir(exist_ok=True)
os.environ['TMP']=str(temporary)
os.environ['TEMP']=str(temporary)
base='https://mail.example.test'
owner='browser-test-owner-password-00000000'
sock=socket.socket(); sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]; sock.close()
env={k:v for k,v in os.environ.items() if not k.startswith('MAIL_BRIDGE_') and k!='CREDENTIALS_DIRECTORY'}
env.update(MAIL_BRIDGE_OWNER_PASSWORD=owner,MAIL_BRIDGE_PUBLIC_URL=base,MAIL_BRIDGE_OAUTH_REDIRECT_URIS=json.dumps(['http://127.0.0.1/callback']),MAIL_BRIDGE_DATA_DIR=str(work),MAIL_BRIDGE_BIND=f'127.0.0.1:{port}',MAIL_BRIDGE_EVENTS_ENABLED='false')
process=subprocess.Popen([str(args.server_binary.resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def request(path,body=None):
    data=None if body is None else json.dumps(body).encode()
    req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=data,headers={'Content-Type':'application/json'})
    return json.loads(urllib.request.urlopen(req,timeout=5).read())
for _ in range(50):
    try: request('/.well-known/oauth-protected-resource'); break
    except OSError: time.sleep(.1)

class Callback(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_GET(self):
        self.server.received=True
        self.server.query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        self.send_response(200); self.end_headers(); self.wfile.write(b'Callback received by isolated test')

receiver=http.server.ThreadingHTTPServer(('127.0.0.1',0),Callback)
receiver.received=False
threading.Thread(target=receiver.serve_forever,daemon=True).start()
callback=f'http://127.0.0.1:{receiver.server_port}/callback'
verifier='a'*64
challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
try:
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(executable_path=str(args.browser.resolve()),headless=True)
        for case in ['actual-server-headers']:
            receiver.received=False
            observed={}
            context=browser.new_context()
            page=context.new_page()
            client=request('/oauth/register',{'redirect_uris':[callback],'token_endpoint_auth_method':'none'})['client_id']
            params={'client_id':client,'redirect_uri':callback,'response_type':'code','code_challenge':challenge,'code_challenge_method':'S256','resource':base+'/mcp','state':'isolated-test','scope':'mail:read'}
            def route_handler(route):
                req=route.request
                url=urllib.parse.urlsplit(req.url)
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                headers=dict(req.all_headers())
                headers['host']='mail.example.test'
                connection.request(req.method,url.path+('?' + url.query if url.query else ''),body=req.post_data_buffer,headers=headers)
                response=connection.getresponse()
                response_headers=dict(response.getheaders())
                body=response.read(); connection.close()
                if req.method=='POST':
                    observed.update(post_origin=headers.get('origin'),post_status=response.status,post_referer=headers.get('referer'))
                route.fulfill(status=response.status,headers=response_headers,body=body)
            context.route(base+'/**',route_handler)
            page.goto(base+'/oauth/authorize?'+urllib.parse.urlencode(params))
            page.locator('[name="owner_password"]').fill(owner)
            page.locator('button[type="submit"]').click(no_wait_after=True)
            page.wait_for_timeout(1200)
            observed.update(case=case,callback_received=receiver.received)
            assert observed['post_origin']==base, 'Browser POST must retain its actual origin'
            assert observed['post_referer']==base+'/', 'Authorization query must not leak through Referer'
            assert observed['post_status']==303, 'Synthetic owner consent must succeed'
            assert receiver.received, 'Browser CSP must permit the registered callback'
            assert receiver.query['state']==['isolated-test']
            assert receiver.query['iss']==[base]
            exchange={'grant_type':'authorization_code','client_id':client,'redirect_uri':callback,'code':receiver.query['code'][0],'code_verifier':verifier,'resource':base+'/mcp'}
            req=urllib.request.Request(f'http://127.0.0.1:{port}/oauth/token',data=urllib.parse.urlencode(exchange).encode(),headers={'Content-Type':'application/x-www-form-urlencoded'})
            tokens=json.loads(urllib.request.urlopen(req,timeout=5).read())
            assert tokens.get('access_token') and tokens.get('scope')=='mail:read'
            observed.update(synthetic_token_exchange=True,scope=tokens['scope'],real_credentials_used=False)
            def tool(name, arguments):
                data=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':arguments}}).encode()
                req=urllib.request.Request(f'http://127.0.0.1:{port}/mcp',data=data,headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','Authorization':'Bearer '+tokens['access_token'],'MCP-Protocol-Version':'2025-06-18','Host':'mail.example.test'})
                result=json.loads(urllib.request.urlopen(req,timeout=5).read())['result']
                assert not result.get('isError'), 'MCP tool must succeed'
                return json.loads(result['content'][0]['text'])
            assert tool('list_accounts',{})['account_count']==0
            invitation=tool('begin_account_setup',{})
            page.goto(invitation['setup_url'])
            assert page.locator('[name="password"]').get_attribute('type')=='password'
            for name,value in {'account_id':'browser-test','name':'浏览器测试','email':'test@example.com','imap_host':'imap.example.com','imap_port':'993','password':'synthetic-browser-mailbox-password','owner_password':owner}.items():
                page.locator('[name="'+name+'"]').fill(value)
            page.locator('button[type="submit"]').click()
            page.wait_for_load_state()
            assert '邮箱已添加' in page.locator('h1').inner_text()
            assert observed['post_origin']==base
            assert observed['post_referer']==base+'/'
            assert observed['post_status']==200
            accounts=tool('list_accounts',{})
            assert accounts['account_count']==1 and accounts['accounts'][0]['account_id']=='browser-test'
            assert accounts['accounts'][0]['smtp_enabled'] is False and accounts['accounts'][0]['connection_tested'] is False
            assert 'synthetic-browser-mailbox-password' not in json.dumps(accounts)
            # Reopen the real process with the same DB; no account configuration env/files exist.
            process.terminate(); process.wait(timeout=5)
            process=subprocess.Popen([str(args.server_binary.resolve())],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(50):
                try: request('/.well-known/oauth-protected-resource'); break
                except OSError: time.sleep(.1)
            assert tool('list_accounts',{})==accounts
            observed.update(private_browser_setup=True,hot_account_activation=True,accounts_survive_restart=True,existing_oauth_survives_restart=True,mailbox_login_attempted=False,email_sent=False)
            print(json.dumps(observed),flush=True)
            context.close()
        browser.close()
finally:
    receiver.shutdown()
    process.terminate(); process.wait(timeout=5)
