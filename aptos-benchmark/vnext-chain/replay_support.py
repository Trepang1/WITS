"""Configuration and BCS state encoders for local Aptos VM replays."""

import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
BENCH = SOURCE.parent
REPO = BENCH.parent
RUNTIME = Path(os.environ.get('WTAS_APTOS_RUNTIME', REPO / '.aptos-runtime')).expanduser().resolve()
CLI = Path(os.environ.get('WTAS_APTOS_CLI', RUNTIME / 'tools/aptos')).expanduser().resolve()
RUN_ROOT = Path(os.environ.get('WTAS_BENCH_RUN_DIR', REPO / 'runs/reproduction')).expanduser().resolve()
VM_RUN = RUN_ROOT / 'vnext-chain'
PROFILE = os.environ.get('WTAS_APTOS_PROFILE', 'bench')
ADDR = os.environ.get('WTAS_APTOS_ADDRESS', '').lower().removeprefix('0x').zfill(64)
API = 'http://127.0.0.1:8080/v1'
GAS_PATH = '/accounts/0x1/resource/0x1::gas_schedule::GasScheduleV2'
FEATURES_PATH = '/accounts/0x1/resource/0x1::features::Features'
PINS = json.loads((BENCH / 'versions.json').read_text())
EXPORTER = RUNTIME / 'build/exporter-target/release/wtas-vnext-chain-export'
MOVE_PACKAGES = {'wits': 'WTAS_Current_VNext', 'das': 'Das_Rust_Reference'}


def bytecode_dir(scheme):
    return RUNTIME / 'build' / scheme / 'build' / MOVE_PACKAGES[scheme] / 'bytecode_modules'


def check_cli():
    if not CLI.is_file():
        raise FileNotFoundError(f'{CLI}. Run bootstrap_aptos.py or set WTAS_APTOS_CLI.')
    version = subprocess.check_output([str(CLI), '--version'], text=True).strip()
    if version != 'aptos 9.6.0':
        raise RuntimeError(f'Expected Aptos CLI 9.6.0, got {version!r}')


def check_address():
    if not re.fullmatch(r'[0-9a-f]{64}', ADDR) or ADDR == '0' * 64:
        raise ValueError('Set WTAS_APTOS_ADDRESS to the funded local profile address.')


def get(path=''):
    with urllib.request.urlopen(API + path, timeout=15) as response:
        return json.load(response)


def load_environment():
    check_cli()
    check_address()
    try:
        node = get()
    except OSError as exc:
        raise RuntimeError('Start the pinned localnet on 127.0.0.1:8080 first. See APTOS.md.') from exc
    if node['chain_id'] != 4 or node['git_hash'] != PINS['framework_commit']:
        raise RuntimeError('The loopback node does not match the pinned localnet commit and chain ID.')
    gas = get(GAS_PATH)['data']
    features = get(FEATURES_PATH)['data']
    if gas != json.loads((BENCH / 'gas-schedule.json').read_text())['data']:
        raise RuntimeError('The localnet gas schedule differs from the paper pin.')
    if features != json.loads((BENCH / 'features.json').read_text())['data']:
        raise RuntimeError('The localnet feature flags differ from the paper pin.')
    get('/accounts/0x' + ADDR)
    VM_RUN.mkdir(parents=True, exist_ok=True)
    path = VM_RUN / 'ENVIRONMENT.json'
    current = dict(node=node, gas_schedule=gas, features=features, address=ADDR, profile=PROFILE,
                   cli='aptos9.6.0', transactions_submitted=False)
    if path.exists():
        env = json.loads(path.read_text())
        if any(env.get(key) != current[key] for key in ('gas_schedule', 'features', 'address', 'profile')):
            raise RuntimeError('This output belongs to a different local account or environment. Choose a new run directory.')
        get('/accounts/0x' + ADDR + '?ledger_version=' + str(env['snapshot']))
        return env
    env = dict(snapshot=node['ledger_version'], **current)
    path.write_text(json.dumps(env, indent=2) + '\n')
    return env


def leb(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def vec(data):
    return leb(len(data)) + data


def schedule_bytes(schedule):
    return (int(schedule['feature_version']).to_bytes(8, 'little') + leb(len(schedule['entries']))
            + b''.join(vec(entry['key'].encode()) + int(entry['val']).to_bytes(8, 'little')
                       for entry in schedule['entries']))


def legacy_state(data):
    return (b'\x00' + vec(data)).hex()


def execution_fee(summary, log_path):
    fee = summary.get('fee_statement')
    if fee is None:
        raise RuntimeError(
            f"VM discarded the call ({summary['status']}). "
            f"Check the local account balance and inspect {log_path}."
        )
    return fee
