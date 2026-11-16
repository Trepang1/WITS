"""Check the frozen paper data and optionally compare regenerated figure data."""

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


DATA = Path(__file__).resolve().parent
ROOT = DATA.parent
DAS = ROOT / 'aptos-benchmark/das-rust'
HISTORICAL = ROOT / 'aptos-benchmark/paper-comparison-20261028'
SIZES = (32, 64, 128, 256, 512)
SCHEMES = ('ours', 'das', 'garg')
CASES = {(n, scheme) for n in SIZES for scheme in SCHEMES}
LABELS = {'ours': 'WITS', 'das': 'Das23 (BLS)', 'garg': 'Garg24 (reference)'}


def rows(path):
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream))


def validate_hashes():
    manifest = json.loads((DATA / 'manifest.json').read_text(encoding='utf-8'))
    for name, expected in manifest['sha256'].items():
        value = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        if value != expected:
            raise ValueError(f'SHA-256 mismatch: {name}')


def validate_host():
    samples = defaultdict(list)
    for sample in rows(DATA / 'host-samples.csv'):
        samples[(int(sample['n']), sample['scheme'])].append(sample)
    assert set(samples) == CASES
    for group in samples.values():
        assert sorted(int(row['seed']) for row in group) == list(range(5))
        assert all(int(row['k']) == int(row['n']) // 2 for row in group)

    groups = {(int(row['n']), row['scheme']): row
              for row in rows(DAS / 'replacement_time_summary.csv')}
    original = {(int(row['n']), row['scheme']): row
                for row in rows(HISTORICAL / 'time_summary.csv')}
    assert set(groups) == CASES
    published = rows(DATA / 'published-figures/cpu-host-comparison-data.csv')
    assert len(published) == 75
    for row in published:
        scheme = next(key for key, label in LABELS.items() if label == row['scheme'])
        key = (int(row['n']), scheme)
        if scheme != 'das':
            assert groups[key] == original[key]
        metric = row['metric']
        values = [float(sample[metric]) for sample in samples[key]]
        for statistic, value in [('mean', statistics.mean(values)),
                                 ('min', min(values)), ('max', max(values))]:
            stored = float(row[f'{statistic}_ms'])
            assert stored == float(groups[key][f'{metric}_{statistic}'])
            assert math.isclose(stored, value, rel_tol=1e-12, abs_tol=1e-12), (key, metric, statistic)


def validate_vm():
    vm = rows(DAS / 'chain-results/three_scheme_summary.csv')
    full = {(int(row['n']), row['scheme']): row for row in vm}
    assert len(vm) == len(CASES) and set(full) == CASES
    assert all(row['complete_honest'] == 'True' for row in vm)
    stage_groups = defaultdict(list)
    for row in rows(HISTORICAL / 'chain_step_gas.csv'):
        stage_groups[(int(row['n']), row['scheme'])].append(float(row['execution_gas']))
    for row in rows(DAS / 'chain-results/step_gas.csv'):
        stage_groups[(int(row['n']), 'das')].append(float(row['execution_gas']))
    assert set(stage_groups) == CASES
    for key, costs in stage_groups.items():
        assert math.isclose(sum(costs), float(full[key]['execution_gas']), abs_tol=1e-5)

    attempts = defaultdict(dict)
    for row in rows(DATA / 'cap-attempts.csv'):
        attempts[(int(row['n']), row['scheme'])][int(row['multiplier'])] = row
    assert set(attempts) == {(n, scheme) for n in (256, 512) for scheme in ('ours', 'garg')}
    assert sum(len(group) for group in attempts.values()) == 16
    for row in rows(DATA / 'cap-summary.csv'):
        key = (int(row['n']), 'ours' if row['scheme'] == 'WITS' else 'garg')
        assert float(row['execution_gas']) == float(full[key]['execution_gas'])
        assert row['same_full_cost_at_all_successful_budgets'] == 'True'
        assert row['equals_frozen_full_cost'] == 'True'
        for factor in (1, 2, 4, 8):
            attempt = attempts[key][factor]
            assert int(attempt['execution_cap']) == 9200 * factor
            assert attempt['success'] == row[f'pass_{factor}x']
        assert len({a['argument_sha256'] for a in attempts[key].values()}) == 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rendered-dir', type=Path)
    args = parser.parse_args()
    validate_hashes()
    validate_host()
    validate_vm()
    print('Verified frozen hashes, 75 host runs, 15 VM cases, and 16 cap attempts.')
    if args.rendered_dir is not None:
        for expected in sorted((DATA / 'published-figures').glob('*.csv')):
            assert rows(expected) == rows(args.rendered_dir / expected.name), expected.name
        print('Regenerated figure data exactly match the published numerical records.')


if __name__ == '__main__':
    main()
