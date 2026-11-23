"""Run an opt-in bounded Claude Code task through its configured Messages gateway."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from secrets import compare_digest, token_urlsafe
import signal
from subprocess import Popen, PIPE, TimeoutExpired
from threading import Lock, Thread
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from answer_evidence import SELECTION_SCHEMA, render_transcript
from answer_phase import final_answer_request, has_no_followup_budget


MAX_CALLS = 4
MAX_INPUT_BYTES = 120 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SECONDS = 90


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@contextmanager
def relay(base, key, deadline, *, send=None, structured_output=False):
    host = urlsplit(base)
    if host.scheme != 'https' or not host.hostname or host.username or host.password or host.query or host.fragment or not key:
        raise ValueError('Bounded answering requires the configured HTTPS Messages gateway and API key.')
    upstream = base.rstrip('/').removesuffix('/v1')
    token = token_urlsafe(32)
    budget = Lock()
    calls = total = 0

    def forward(path, body, headers, timeout):
        opener = build_opener(ProxyHandler({}), NoRedirect())
        with opener.open(Request(upstream + path, json.dumps(body).encode(), headers, method='POST'), timeout=timeout) as response:
            return response.status, response.headers.get('Content-Type', 'application/json'), response.read(MAX_RESPONSE_BYTES + 1)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, media, content):
            try:
                self.send_response(status)
                self.send_header('Content-Type', media)
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def reject(self, status, message):
            self.reply(status, 'application/json', json.dumps({'type': 'error', 'error': {
                'type': 'invalid_request_error', 'message': message,
            }}).encode())

        def do_POST(self):
            nonlocal calls, total
            if self.path not in ('/v1/messages', '/v1/messages?beta=true') or not compare_digest(
                    self.headers.get('x-api-key', '').encode(), token.encode()):
                self.reject(403, 'Unrecognised bounded task request.')
                return
            try:
                size = int(self.headers.get('Content-Length', 0))
            except ValueError:
                size = 0
            with budget:
                remaining = deadline - monotonic()
                if size < 1 or total + size > MAX_INPUT_BYTES or calls >= MAX_CALLS or remaining <= 0:
                    self.reject(400, 'The bounded task budget is exhausted.')
                    return
                calls += 1
                attempt = calls
                total += size
                remaining_bytes = MAX_INPUT_BYTES - total
            self.connection.settimeout(remaining)
            try:
                body = json.loads(self.rfile.read(size))
                output_tokens = body.get('max_tokens', 1200)
                if type(output_tokens) is not int or output_tokens < 1:
                    raise ValueError
                body['max_tokens'] = min(output_tokens, 1200)
                if body.get('tools') and has_no_followup_budget(attempt, MAX_CALLS, remaining_bytes, size):
                    final_answer_request(body, tool_free=True, structured_output=structured_output)
                headers = {'content-type': 'application/json', 'x-api-key': key}
                headers.update({name: self.headers[name] for name in ('anthropic-version', 'anthropic-beta') if name in self.headers})
                status, media, content = (send or forward)(self.path, body, headers, max(.001, deadline - monotonic()))
                if len(content) > MAX_RESPONSE_BYTES:
                    self.reject(502, 'The Messages response exceeded the task limit.')
                    return
                self.reply(status, media, content)
            except HTTPError as exc:
                self.reject(exc.code if 400 <= exc.code < 600 else 502, 'The configured gateway rejected the request.')
            except (OSError, URLError, TimeoutError, AttributeError, TypeError, ValueError):
                self.reject(502, 'The configured gateway could not complete this bounded request.')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', token
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run_answer(command, prompt, cwd, model, *, verified_specialists=None):
    deadline = monotonic() + SECONDS
    verified = verified_specialists is not None
    if verified:
        command = [*command, '--output-format', 'stream-json', '--verbose', '--json-schema', json.dumps(SELECTION_SCHEMA)]
    with relay(model['ANTHROPIC_BASE_URL'], model['ANTHROPIC_API_KEY'], deadline,
               structured_output=verified) as (base, token):
        env = os.environ | {'ANTHROPIC_BASE_URL': base, 'ANTHROPIC_API_KEY': token, 'ANTHROPIC_MAX_RETRIES': '0',
                            'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_AUTOUPDATER': '1',
                            'CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY': '0', 'NO_PROXY': '127.0.0.1,localhost'}
        env.pop('ANTHROPIC_AUTH_TOKEN', None)
        with Popen(command, cwd=cwd, env=env, stdin=PIPE, stdout=PIPE if verified else None,
                   text=True, start_new_session=True) as process:
            try:
                output, _ = process.communicate(prompt, timeout=max(.001, deadline - monotonic()))
            except (TimeoutExpired, KeyboardInterrupt):
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                raise
            if verified:
                answer, state = render_transcript(output, verified_specialists, prompt=prompt)
                print(answer)
                if state == 'invalid_selection':
                    return process.returncode or 1
            return process.returncode
