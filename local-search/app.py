"""Start the pinned loopback service and open the dedicated Claude Code profile."""
import argparse
from contextlib import closing
from datetime import datetime
import json
import os
from pathlib import Path
import secrets
from shutil import which
import socket
import sqlite3
from subprocess import run, TimeoutExpired
import sys
import tempfile
from time import monotonic, sleep, time
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evaluation/mcp_selection/replacement'))
from local_profile import (ACTIVE_CONFIG, BUILD, ENDPOINT, LOCAL_SEARCH, ROOT, SERVICE, STATE, activate_profile,
                           command, route_guidance, search_policy, servers)
from answer_evidence import SELECTION_GUIDANCE
from answer_task import run_answer

NAME = SERVICE.get('name', 'osws-personal-search')
IMAGE = 'ghcr.io/searxng/searxng@sha256:932f69dca010db9880bddebb2171f05d8e1a25d04a59149ff65409993d680024'
HOST, PORT = '127.0.0.1', SERVICE.get('port', 8892)
SETTINGS = LOCAL_SEARCH / 'searxng.yml'
BINDS = {'/etc/searxng/settings.yml': SETTINGS,
         '/usr/local/searxng/searx/engines/freeserp.py': LOCAL_SEARCH / 'freeserp.py'}
MEMORY = 256 * 1024 * 1024
# Do not include the container environment (which contains its server secret).
INSPECT = ('{{.ImageDigest}}\n{{.State.Status}}\n{{json .NetworkSettings.Ports}}\n'
           '{{json .Mounts}}\n{{.HostConfig.Memory}}\n{{.HostConfig.NanoCpus}}')
SESSION_TOOLS = ','.join(f'mcp__searxng__{tool}' for tool in
                         ('searxng_web_search', 'web_url_read', 'searxng_instance_info', 'huggingface_catalog'))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def podman(*args, seconds=10, env=None):
    binary = which('podman')
    if not binary:
        raise RuntimeError('Podman is not on PATH. Install Podman before starting local search.')
    try:
        return run([binary, *args], capture_output=True, text=True, timeout=seconds, env=env)
    except TimeoutExpired as exc:
        raise RuntimeError('Podman did not respond. Check `podman machine list` and try status again.') from exc


def inspect_service():
    exists = podman('container', 'exists', NAME)
    if exists.returncode == 1:
        return None
    if exists.returncode:
        raise RuntimeError('Cannot reach Podman. Check `podman machine list`; start your existing VM with `podman machine start`.')
    result = podman('container', 'inspect', '--format', INSPECT, NAME)
    if result.returncode:
        # A concurrent stop can remove an auto-removed container between the two calls.
        if podman('container', 'exists', NAME).returncode == 1:
            return None
        raise RuntimeError(f'Cannot inspect {NAME}. Check `podman ps -a`.')
    digest, state, ports, mounts, memory, cpus = result.stdout.strip().splitlines()
    bindings = {m['Destination']: m['Source'] for m in json.loads(mounts)
                if m.get('Type') == 'bind' and m.get('RW') is False and m.get('Destination') in BINDS}
    if (digest != IMAGE.split('@')[1] or json.loads(ports) != {'8080/tcp': [{'HostIp': HOST, 'HostPort': str(PORT)}]}
            or bindings != {target: str(source) for target, source in BINDS.items()}
            or int(memory) != MEMORY or int(cpus) != 10**9):
        raise RuntimeError(f'{NAME} does not match this project’s pinned service, port, or settings. '
                           'Inspect it with `podman ps -a` and resolve the conflict before using this app.')
    return state


def port_in_use():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((HOST, PORT)) == 0


def catalogue():
    with build_opener(ProxyHandler({}), NoRedirect()).open(ENDPOINT + '/config', timeout=1) as res:
        data = json.loads(res.read(128 * 1024))
    return {row['name'] for row in data['engines'] if row['enabled']}, data.get('instance_name')


def ready():
    try:
        enabled, name = catalogue()
    except (OSError, ValueError, TypeError, KeyError):
        return False
    policy = search_policy()
    return enabled == (set(policy['preferred']) | set(policy['specialists'].values())) and name == 'Local project search'


def start_service():
    state = inspect_service()
    if state == 'running' and ready():
        return 'reused'
    mode = 'reused'
    if state is None:
        for source in BINDS.values():
            if not source.is_file():
                raise RuntimeError(f'The pinned SearXNG file is missing. Restore local-search/{source.name}.')
        if port_in_use() and inspect_service() is None:
            raise RuntimeError(f'Port {HOST}:{PORT} is occupied by another process. Free it before launching search.')
        if podman('image', 'exists', IMAGE).returncode:
            raise RuntimeError(f'The pinned image is not cached. Run `podman pull {IMAGE}` during setup.')
        env = os.environ | {'SEARXNG_SECRET': secrets.token_hex(32)}
        volumes = [arg for target, source in BINDS.items() for arg in ('-v', f'{source}:{target}:ro')]
        result = podman('run', '--rm', '-d', '--name', NAME, '--pull=never', '--cpus=1', '--memory=256m',
                        '-p', f'{HOST}:{PORT}:8080', '-e', 'SEARXNG_SECRET', '-e', 'GRANIAN_WORKERS=1',
                        '-e', 'GRANIAN_INTERFACE=wsgi', *volumes,
                        IMAGE, seconds=20, env=env)
        if result.returncode and inspect_service() not in {'running', 'created', 'configured'}:
            raise RuntimeError(f'Could not start {NAME}. Check `podman ps -a` and whether port {PORT} is free.')
        if not result.returncode:
            mode = 'started'
    elif state in {'exited', 'stopped', 'created', 'configured'}:
        if podman('start', NAME, seconds=20).returncode and inspect_service() != 'running':
            raise RuntimeError(f'Could not restart {NAME}. Check `podman logs {NAME}`.')
        mode = 'restarted'
    elif state != 'running':
        raise RuntimeError(f'{NAME} is {state}. Check `podman ps -a` before launching search.')
    deadline = monotonic() + 12
    while monotonic() < deadline:
        if ready() and inspect_service() == 'running':
            return mode
        sleep(0.25)
    raise RuntimeError(f'{NAME} did not expose the pinned catalogue at {ENDPOINT}. Check `podman logs {NAME}`.')


def check_profile(*, create=False):
    node = which('node')
    if not node or not BUILD.is_file():
        raise RuntimeError('The pinned MCP build or Node.js is missing. See README.md for prerequisites and run ./web-search setup.')
    version = run([node, '--version'], capture_output=True, text=True, timeout=5)
    if version.returncode or not version.stdout.startswith('v24.'):
        raise RuntimeError('Use Node.js 24 with the pinned MCP build (see README.md).')
    if not ACTIVE_CONFIG.exists() and create:
        try:
            activate_profile()
        except FileExistsError:  # Another launch may have created the same profile.
            pass
    if not ACTIVE_CONFIG.is_file():
        raise RuntimeError('The dedicated MCP profile is missing. Launch ./web-search to generate it.')
    if installed_policy() != search_policy():
        raise RuntimeError('The dedicated MCP profile uses a different routing policy. Run ./web-search setup --rebuild.')


def installed_policy():
    """Only upgrade a private profile matching our generated template."""
    message = 'The dedicated MCP profile has unexpected settings. See the rebuild and rollback instructions in README.md.'
    if ACTIVE_CONFIG.is_symlink() or ACTIVE_CONFIG.stat().st_mode & 0o077:
        raise RuntimeError(message)
    try:
        current = json.loads(ACTIVE_CONFIG.read_text())
        prefix = 'OSWS_SEARCH_POLICY='
        args = current['mcpServers']['searxng']['args']
        policy = json.loads(next(arg[len(prefix):] for arg in args if arg.startswith(prefix)))
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError) as exc:
        raise RuntimeError(message) from exc
    if not isinstance(policy, dict) or current != {'mcpServers': servers(BUILD, policy=policy)}:
        raise RuntimeError(message)
    return policy


def save_json(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def saved_source_state():
    if not STATE.is_file():
        return {}
    with closing(sqlite3.connect(STATE.as_uri() + '?mode=ro', uri=True, timeout=0.25)) as db:
        return {engine: (until, reason) for engine, until, reason in db.execute(
            'SELECT engine, until_ms, status FROM source_state')}


def show_status():
    state = inspect_service()
    listening = state == 'running' and ready()
    state_label = 'ready' if listening else ('running, catalogue unavailable' if state == 'running' else state or 'stopped')
    print(f'SearXNG: {state_label} ({ENDPOINT})')
    problem = None
    try:
        check_profile()
        print('Dedicated MCP profile: ready')
    except (OSError, ValueError, RuntimeError, TimeoutExpired) as exc:
        problem = exc
        print(f'Dedicated MCP profile: {exc}')
    policy = search_policy()
    order = ' → '.join(policy['preferred'])
    print(f'General: adaptive (default tie-break {order})' if policy.get('adaptive') else f'General: {order}')
    try:
        rows = saved_source_state()
    except sqlite3.Error:
        print('Saved pacing and pause state could not be read.')
    else:
        for engine in dict.fromkeys([*policy['preferred'], *policy['specialists'].values()]):
            if engine == 'huggingface datasets':  # The Hub routes share a budget.
                continue
            until, reason = rows.get(engine, (0, ''))
            if engine == 'huggingface':
                dataset = rows.get('huggingface datasets', (0, ''))
                if dataset[0] > until:
                    until, reason = dataset
            if policy['sources'].get(engine, {}).get('min_interval_ms', 0) is None:
                eligibility = 'disabled in routing policy'
            elif reason in ('CAPTCHA', 'access denied'):
                eligibility = ('paused after CAPTCHA or bot verification; no automatic retry' if reason == 'CAPTCHA'
                               else 'paused after access denial; no automatic retry')
            elif until > time() * 1000:
                end = datetime.fromtimestamp(until / 1000).astimezone().isoformat(timespec='seconds')
                eligibility = f'cooling down ({reason}) until {end}'
            else:
                eligibility = 'eligible under saved limits' if until else 'no saved pause or dispatch'
            print(f'  {engine}: {eligibility}')
    print('Specialist routes: ' + ', '.join(policy['specialists'].values()) + '; direct public URL reading')
    print('Status checks only local configuration and saved limits; it does not probe providers or the model.')
    return 0 if listening and problem is None else 1


def setup(*, rebuild=False):
    for executable in ('node', 'npm', 'patch', 'podman', 'claude'):
        if not which(executable):
            raise RuntimeError(f'{executable} is missing from PATH; see README.md for prerequisites.')
    version = run(['node', '--version'], capture_output=True, text=True, timeout=5)
    if version.returncode or not version.stdout.startswith('v24.'):
        raise RuntimeError('Setup requires Node.js 24.')
    if podman('info', '--format', '{{.Host.OS}}', seconds=20).returncode:
        raise RuntimeError('Start Podman before setup. On macOS use podman machine start.')
    if podman('image', 'exists', IMAGE).returncode:
        print('Downloading the pinned SearXNG image.', flush=True)
        result = podman('pull', IMAGE, seconds=300)
        if result.returncode:
            raise RuntimeError(f'Could not fetch the pinned image. Try podman pull {IMAGE}.')
    installed = BUILD.parents[1]
    previous = installed_policy() if rebuild and BUILD.is_file() and ACTIVE_CONFIG.exists() else None
    if rebuild or not BUILD.is_file():
        npm_dir = ROOT / 'evaluation/mcp_selection'
        npm_package = npm_dir / 'node_modules/mcp-searxng/package.json'
        if not rebuild or not npm_package.is_file():
            if run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', str(npm_dir)],
                   timeout=360).returncode:
                raise RuntimeError('Could not install the pinned npm dependencies.')
        with tempfile.TemporaryDirectory(dir=LOCAL_SEARCH) as scratch:
            target = Path(scratch) / 'build'
            builder = npm_dir / 'replacement/prepare.py'
            if run([sys.executable, '-B', str(builder), str(target), '--local-routing'], timeout=60).returncode:
                raise RuntimeError('Could not build the pinned MCP server.')
            backup = None
            if rebuild and installed.is_dir():
                backup = Path(tempfile.mkdtemp(prefix='.build-budgeted-rollback-', dir=LOCAL_SEARCH))
                if previous is not None:
                    os.link(ACTIVE_CONFIG, backup / 'mcp.json')
                    save_json(backup / 'routing.json', previous)
            desired = search_policy()
            profile = Path(scratch) / 'mcp.json'
            if previous is not None and desired != previous:
                # Check the candidate policy with a disposable budget DB before swapping files.
                cli = target / 'dist' / 'cli.js'
                probe = servers(cli, policy=desired, state=Path(scratch) / 'state.sqlite3')['searxng']
                init = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                    'protocolVersion': '2024-11-05', 'capabilities': {},
                    'clientInfo': {'name': 'setup-check', 'version': '1.0'},
                }})
                # The CLI exits at EOF. Check its initialization response instead of exit status alone.
                verified = run([probe['command'], *probe['args']], input=init + '\n', capture_output=True,
                               text=True, timeout=10)
                if verified.returncode or not any('result' in json.loads(line)
                                                  for line in verified.stdout.splitlines()):
                    raise RuntimeError('The new routing policy did not initialize. The previous build is still installed.')
                save_json(profile, {'mcpServers': servers(BUILD, policy=desired)})
            if backup is not None:
                installed.rename(backup / installed.name)
            try:
                target.rename(installed)
                if profile.exists():
                    profile.replace(ACTIVE_CONFIG)
            except OSError:
                if installed.exists():
                    installed.rename(target)
                if backup is not None:
                    (backup / installed.name).rename(installed)
                raise
            if backup is not None:
                print(f'Previous build and available profile saved for rollback at {backup}.')
    check_profile(create=True)
    print('Setup complete. Run ./web-search to open Claude Code.')
    return 0


def main():
    parser = argparse.ArgumentParser(prog='./web-search', description=__doc__)
    sub = parser.add_subparsers(dest='action')
    start = sub.add_parser('start', help='start or reuse SearXNG and launch Claude Code')
    start.add_argument('--service-only', action='store_true', help='start or reuse only SearXNG')
    start.add_argument('--prompt', help='run one non-interactive Claude turn')
    answer_mode = start.add_mutually_exclusive_group()
    answer_mode.add_argument('--finish-with-evidence', action='store_true', help='reserve a model request for answering')
    answer_mode.add_argument('--verified-evidence', action='store_true', help='return checked publisher quotations or report missing evidence')
    setup_parser = sub.add_parser('setup', help='install the pinned local dependencies and create the profile')
    setup_parser.add_argument('--rebuild', action='store_true', help='build locally and retain the old MCP for rollback')
    sub.add_parser('status', help='inspect local service and persisted source eligibility')
    sub.add_parser('stop', help='stop this project’s SearXNG service without resetting budgets')
    args = parser.parse_args()
    try:
        if args.action == 'setup':
            return setup(rebuild=args.rebuild)
        if args.action == 'status':
            return show_status()
        if args.action == 'stop':
            state = inspect_service()
            if state == 'running':
                if podman('stop', NAME, seconds=20).returncode and inspect_service() == 'running':
                    raise RuntimeError(f'Could not stop {NAME}. Check `podman ps -a`.')
                print(f'Stopped {NAME}; saved source limits were preserved.')
            else:
                print(f'{NAME} is not running; saved source limits were preserved.')
            return 0
        service_only = getattr(args, 'service_only', False)
        prompt = getattr(args, 'prompt', None)
        if service_only and prompt:
            parser.error('--prompt requires a Claude session')
        bounded = getattr(args, 'finish_with_evidence', False)
        verified = getattr(args, 'verified_evidence', False)
        if (bounded or verified) and not prompt:
            parser.error('The selected answer mode requires --prompt')
        if not service_only:
            claude = which('claude')
            if not claude:
                raise RuntimeError('Claude Code is not on PATH. Install it or open your existing Claude Code shell.')
            check_profile(create=True)
            model = {name: os.environ.get(name, '') for name in ('ANTHROPIC_BASE_URL', 'ANTHROPIC_API_KEY')}
        print(f'Local SearXNG {start_service()} at {ENDPOINT}.', flush=True)
        if bounded or verified:
            guidance = route_guidance() + ('\n' + SELECTION_GUIDANCE if verified else '')
            direct = command(claude, ACTIVE_CONFIG, routing=guidance)
            direct += ['--allowedTools', SESSION_TOOLS, '--print', '--no-session-persistence', '--permission-mode',
                       'dontAsk', '--max-turns', '4']
            specialists = set(search_policy()['specialists'].values()) if verified else None
            return run_answer(direct, prompt, ROOT, model, verified_specialists=specialists)
        if not service_only:
            launcher = ROOT / 'evaluation/mcp_selection/replacement/local_profile.py'
            args = [sys.executable, '-B', str(launcher), '--allowedTools', SESSION_TOOLS]
            if prompt:
                args += ['--print', '--no-session-persistence', '--permission-mode', 'dontAsk', '--max-turns', '4', '--', prompt]
            os.execv(sys.executable, args)
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutExpired) as exc:
        print(f'Search app: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
