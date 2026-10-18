import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import MailBridge, SafeError, TOOLS, call, parse_mail, utf7_encode, utf7_decode

CONFIG = {'username': 'demo@qq.com', 'from_address': 'demo@qq.com', 'imap_host': 'imap.example.com', 'imap_port': 993, 'imap_security': 'tls', 'smtp_host': 'smtp.example.com', 'smtp_port': 465, 'smtp_security': 'tls', 'smtp_enabled': True}
RAW = b'Subject: =?utf-8?b?5Lit5paH?=\r\nFrom: a@example.com\r\nContent-Type: text/plain; charset=gb18030\r\nContent-Transfer-Encoding: base64\r\n\r\n1tDOxA==\r\n'


class FakeIMAP:
    def __init__(self):
        self.commands = []
        self.validity = b'77'

    def login(self, *args):
        return 'OK', []

    def logout(self):
        pass

    def select(self, folder, readonly):
        assert readonly is True
        self.commands.append(('SELECT', folder, readonly))
        return 'OK', [b'2']

    def response(self, name):
        return name, [self.validity]

    def list(self):
        return 'OK', [b'(\\HasNoChildren) "/" "INBOX"', ('() "/" {9}'.encode(), utf7_encode('中文').encode())]

    def uid(self, command, *args):
        self.commands.append((command, *args))
        if command == 'SEARCH':
            return 'OK', [b'2 10 30']
        uid = args[0].encode()
        if args[1] == '(UID RFC822.SIZE)':
            return 'OK', [b'1 (UID ' + uid + b' RFC822.SIZE ' + str(len(RAW)).encode() + b')']
        return 'OK', [(b'1 (UID ' + uid + b' BODY[] {' + str(len(RAW)).encode() + b'}', RAW), b')']


class FakeSMTP:
    def __init__(self, fail=False, refused=None):
        self.count, self.fail, self.refused = 0, fail, refused or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def login(self, *args):
        pass

    def send_message(self, *args, **kwargs):
        self.count += 1
        if self.fail:
            raise TimeoutError('secret-provider-error')
        return self.refused


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'MAIL_BRIDGE_PASSWORD': 'mock-secret-not-a-real-credential'})
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.imap = FakeIMAP()
        self.smtp = FakeSMTP()
        self.bridge = MailBridge(CONFIG, lambda: self.imap, lambda: self.smtp, Path(self.temp.name) / 'attempts.db')

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_chinese_folder_and_mime(self):
        for value in ('中文&文件夹', 'INBOX', '&', '测试/子文件夹'):
            self.assertEqual(utf7_decode(utf7_encode(value)), value)
        self.assertIn('中文', self.bridge.list_folders()['folders'])
        parsed = parse_mail(RAW, True)
        self.assertEqual(parsed['subject'], '中文')
        self.assertEqual(parsed['body'].strip(), '中文')

    def test_pagination_numeric_uids_and_peek(self):
        first = self.bridge.list_messages(limit=2)
        self.assertEqual([m['uid'] for m in first['messages']], [30, 10])
        self.assertEqual(first['next_before_uid'], 10)
        second = self.bridge.list_messages(limit=2, before_uid=10, uidvalidity=77)
        self.assertEqual([m['uid'] for m in second['messages']], [2])
        self.bridge.read_message(10, 77)
        fetches = [command[-1] for command in self.imap.commands if command[0] == 'FETCH']
        self.assertTrue(all('BODY.PEEK' in f or f == '(UID RFC822.SIZE)' for f in fetches))
        with self.assertRaises(SafeError):
            self.bridge.read_message(10, 78)
        with self.assertRaises(SafeError):
            self.bridge.list_messages(before_uid=10)
        with self.assertRaises(SafeError):
            self.bridge.read_message(10, None)

    def test_search_unicode_and_injection(self):
        self.bridge.search_messages('SUBJECT', '中文')
        self.assertEqual(self.imap.literal, '中文'.encode())
        self.assertIn(('SEARCH', 'UTF-8', 'ALL', 'SUBJECT'), self.imap.commands)
        with self.assertRaises(SafeError):
            self.bridge.search_messages('TEXT', 'x\r\nLOGOUT')

    def test_preview_and_send_dedup_across_restart(self):
        arguments = {'to': ['person@example.com'], 'subject': '中文主题', 'body': '正文'}
        self.assertEqual(self.bridge.prepare_draft(**arguments)['status'], 'preview_only_not_saved_or_sent')
        self.assertEqual(self.smtp.count, 0)
        self.bridge.send_email(**arguments, request_id='request-00000001', confirm_send=True)
        result = MailBridge(CONFIG, smtp_factory=lambda: self.smtp, journal=self.bridge.journal).send_email(**arguments, request_id='request-00000001', confirm_send=True)
        self.assertEqual(self.smtp.count, 1)
        self.assertEqual(result['status'], 'accepted_by_smtp')
        with self.assertRaises(SafeError):
            self.bridge.send_email(**dict(arguments, body='changed'), request_id='request-00000001', confirm_send=True)

    def test_timeout_no_retry_or_provider_error_leak(self):
        self.smtp.fail = True
        args = {'to': ['person@example.com'], 'subject': 'subject', 'body': 'body', 'request_id': 'request-00000002', 'confirm_send': True}
        result = call(self.bridge, 'send_email', args)
        self.assertTrue(result['isError'])
        self.assertNotIn('secret-provider-error', json.dumps(result))
        result = self.bridge.send_email(**args)
        self.assertEqual(result['status'], 'unknown_do_not_retry')
        self.assertEqual(self.smtp.count, 1)

    def test_partial_acceptance(self):
        self.smtp.refused = {'a@example.com': (550, b'refused')}
        args = {'to': ['a@example.com', 'b@example.com'], 'subject': 'subject', 'body': 'body', 'request_id': 'request-00000003', 'confirm_send': True}
        self.assertEqual(self.bridge.send_email(**args)['status'], 'partial_acceptance_do_not_retry')
        self.bridge.send_email(**args)
        self.assertEqual(self.smtp.count, 1)

    def test_send_controls_and_annotations(self):
        for subject, to in [('a\r\nBcc: x@example.com', ['a@example.com']), ('s', ['Name <x@example.com>'])]:
            with self.assertRaises(SafeError):
                self.bridge.prepare_draft(to, subject, 'body')
        with self.assertRaises(SafeError):
            self.bridge.send_email(['x@example.com'], 's', 'b', 'request-00000004', False)
        self.bridge.config = dict(CONFIG, smtp_enabled=False)
        with self.assertRaises(SafeError):
            self.bridge.send_email(['x@example.com'], 's', 'b', 'request-00000004', True)
        send = next(t for t in TOOLS if t['name'] == 'send_email')
        self.assertFalse(send['annotations']['readOnlyHint'])
        self.assertFalse(send['annotations']['idempotentHint'])
        self.assertTrue(call(self.bridge, 'read_message', {'uid': 1, 'uidvalidity': 77, 'password': 'x'})['isError'])

    def test_html_never_executed_and_size_rejected(self):
        raw = b'Content-Type: text/html; charset=utf-8\r\n\r\n<p>Hello</p><script>evil()</script><img src="https://tracker/">'
        parsed = parse_mail(raw, True)
        self.assertIn('Hello', parsed['body'])
        self.assertNotIn('evil', parsed['body'])
        original = self.imap.uid
        def big(command, *args):
            if args[-1] == '(UID RFC822.SIZE)':
                return 'OK', [b'1 (UID 10 RFC822.SIZE 9999999)']
            return original(command, *args)
        self.imap.uid = big
        with self.assertRaises(SafeError):
            self.bridge.read_message(10, 77)

    def test_mandatory_starttls_before_login(self):
        events = []
        class TLSClient(FakeIMAP):
            def starttls(self, **kwargs):
                events.append('tls')
                raise OSError('TLS failed with private provider detail')
            def login(self, *args):
                events.append('login')
        bridge = MailBridge(dict(CONFIG, imap_security='starttls'))
        with patch('server.imaplib.IMAP4', return_value=TLSClient()):
            result = call(bridge, 'list_folders', {})
        self.assertTrue(result['isError'])
        self.assertEqual(events, ['tls'])
        self.assertNotIn('private provider', json.dumps(result))
        self.assertNotIn('mock-secret', json.dumps(call(self.bridge, 'configuration_status', {})))


if __name__ == '__main__':
    unittest.main()
