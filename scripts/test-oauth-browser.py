# /// script
# requires-python = ">=3.11"
# dependencies = ["playwright==1.64.0"]
# ///
"""Browser OAuth regression using only synthetic credentials and local services.

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
parser.add_argument('--server-binary',type=Path,default=root/'mail-bridge-rust/target/debug'/('mail-bridge-rust.exe' if os.name=='nt' else 'mail-bridge-rust'))
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
config=json.loads((root/'mail-bridge-rust/config.example.json').read_text())
(work/'config.json').write_text(json.dumps(config))
sock=socket.socket(); sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]; sock.close()
env={k:v for k,v in os.environ.items() if not k.startswith('MAIL_BRIDGE_') and k!='CREDENTIALS_DIRECTORY'}
env.update(MAIL_BRIDGE_CONFIG=str(work/'config.json'),MAIL_BRIDGE_PASSWORDS_DIR=str(work/'missing-mailboxes'),MAIL_BRIDGE_OWNER_PASSWORD=owner,MAIL_BRIDGE_PUBLIC_URL=base,MAIL_BRIDGE_OAUTH_REDIRECT_URIS=json.dumps(['http://127.0.0.1/callback']),MAIL_BRIDGE_DATA_DIR=str(work),MAIL_BRIDGE_BIND=f'127.0.0.1:{port}',MAIL_BRIDGE_EVENTS_ENABLED='false')
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
            print(json.dumps(observed),flush=True)
            context.close()
        browser.close()
finally:
    receiver.shutdown()
    process.terminate(); process.wait(timeout=5)
