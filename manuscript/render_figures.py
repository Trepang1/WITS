"""Render the two active manuscript figures from validated observations.

WITS/Garg observations remain frozen. The Das host rows use the cross-checked
Rust port, and its Move rows use the full native BLS12-381 verifier. This script
does not execute benchmarks or modify any source measurement.
"""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import sys

sys.dont_write_bytecode = True

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fonts
import numpy as np
from matplotlib.ticker import NullLocator, FuncFormatter


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DAS = ROOT / 'aptos-benchmark/das-rust'
TIME_SOURCE = DAS / 'replacement_time_summary.csv'
CHAIN_SOURCE = DAS / 'chain-results/three_scheme_summary.csv'
FROZEN_TIME = ROOT / 'aptos-benchmark/paper-comparison-20261028/time_summary.csv'
FROZEN_CHAIN = ROOT / 'aptos-benchmark/paper-comparison-20261028/chain_summary.csv'
SIZES = (32, 64, 128, 256, 512)
SCHEMES = ('ours', 'das', 'garg')
LABELS = {'ours': 'WITS', 'das': 'Das23 (BLS)', 'garg': 'Garg24 (reference)'}
STYLE = {'ours': ('#0072B2', 'o', '-'), 'das': ('#D55E00', 's', '--'),
         'garg': ('#009E73', '^', '-.')}


def read_csv(path):
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream))


def provenance(path):
    return {'path': path.relative_to(ROOT).as_posix(),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def write_csv(path, rows):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def configure_style():
    for name in ('times.ttf', 'timesbd.ttf', 'timesi.ttf'):
        path = Path('C:/Windows/Fonts') / name
        if path.exists():
            fonts.fontManager.addfont(path)
    available = {font.name for font in fonts.fontManager.ttflist}
    family = next((name for name in ('Times New Roman', 'Liberation Serif')
                   if name in available), 'DejaVu Serif')
    plt.rcParams.update({'font.family': family,
        'mathtext.fontset': 'stix', 'font.size': 8, 'axes.labelsize': 8,
        'xtick.labelsize': 7.5, 'ytick.labelsize': 7.5, 'pdf.fonttype': 42,
        'svg.fonttype': 'none', 'axes.spines.top': False,
        'axes.spines.right': False})


def save(fig, name, output):
    for ext in ('pdf', 'svg', 'png'):
        fig.savefig(output / f'{name}.{ext}', dpi=300,
                    bbox_inches='tight', pad_inches=.045)
    plt.close(fig)


def host_comparison(output):
    summary = read_csv(TIME_SOURCE)
    frozen = read_csv(FROZEN_TIME)
    assert len(summary) == 15
    for row in summary:
        if row['scheme'] != 'das':
            old = next(r for r in frozen if
                       (r['n'], r['scheme']) == (row['n'], row['scheme']))
            assert row == old, 'WITS/Garg historical host rows changed'
        assert int(row['samples']) == 5
    fig = plt.figure(figsize=(7.16, 4.65))
    grid = fig.add_gridspec(2, 6, left=.075, right=.985, bottom=.105, top=.855,
                           wspace=1.4, hspace=.78)
    slots = [grid[0, 0:2], grid[0, 2:4], grid[0, 4:6],
             grid[1, 1:3], grid[1, 3:5]]
    metrics = [('initialization_ms', '(a) Initialization'),
               ('signer_mean_ms', '(b) Signing per participant'),
               ('aggregation_and_proving_ms', '(c) Aggregation and proof'),
               ('verification_ms', '(d) Complete verification'),
               ('online_total_ms', '(e) Online computation')]
    records = []
    for slot, (field, title) in zip(slots, metrics):
        ax = fig.add_subplot(slot)
        for scheme in SCHEMES:
            group = [next(r for r in summary if
                          int(r['n']) == n and r['scheme'] == scheme) for n in SIZES]
            mean = np.array([float(r[field + '_mean']) for r in group])
            low = np.array([float(r[field + '_min']) for r in group])
            high = np.array([float(r[field + '_max']) for r in group])
            assert np.all(np.isfinite(mean)) and np.all(low > 0)
            assert np.all(low <= mean) and np.all(mean <= high)
            color, marker, line = STYLE[scheme]
            ax.errorbar(SIZES, mean, yerr=[mean-low, high-mean],
                color=color, marker=marker, linestyle=line, linewidth=1.2,
                markersize=3.6, elinewidth=.65, capsize=2, label=LABELS[scheme])
            records.extend({'metric': field, 'n': int(r['n']),
                'scheme': LABELS[scheme], 'samples': int(r['samples']),
                'mean_ms': float(r[field + '_mean']),
                'min_ms': float(r[field + '_min']),
                'max_ms': float(r[field + '_max'])} for r in group)
        ax.set_xscale('log', base=2)
        ax.set_yscale('log')
        ax.set_xticks(SIZES, [str(n) for n in SIZES])
        ax.yaxis.set_minor_locator(NullLocator())
        ax.set_xlabel(r'Committee size $N$', labelpad=3)
        ax.set_ylabel('Time (ms)', labelpad=3)
        ax.set_title(title, fontsize=8.3, pad=7)
        ax.grid(axis='y', which='major', alpha=.22)
    handles, labels = fig.axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', bbox_to_anchor=(.53, .985),
               ncol=3, frameon=False, fontsize=8, handlelength=2.1, columnspacing=2)
    save(fig, 'cpu-host-comparison', output)
    write_csv(output / 'cpu-host-comparison-data.csv', records)
    (output / 'cpu-host-comparison-provenance.json').write_text(json.dumps({
        'source': TIME_SOURCE.relative_to(ROOT).as_posix(),
        'source_sha256': provenance(TIME_SOURCE)['sha256'],
        'original_WITS_Garg_source': provenance(FROZEN_TIME),
        'Das_Rust_source': provenance(DAS / 'summary.csv'),
        'Das_replacement_provenance': provenance(DAS / 'replacement_provenance.json'),
        'samples_per_group': 5, 'error_bars': 'observed minimum and maximum',
        'signing_metric': 'per-participant mean within each instance',
        'online_metric': 'sum of all participant signing work, complete aggregation/proof and verification',
        'first_use_included': False, 'new_benchmarks_run_by_renderer': False,
        'plotted_means': len(records), 'plotted_values_including_ranges': 3*len(records),
        'WITS_Garg_historical_rows_unchanged': True}, indent=2)+'\n', encoding='utf-8')


def chain_comparison(output):
    rows = read_csv(CHAIN_SOURCE)
    frozen = read_csv(FROZEN_CHAIN)
    assert len(rows) == 15
    records = []
    for scheme in SCHEMES:
        for n in SIZES:
            row = next(r for r in rows if int(r['n']) == n and r['scheme'] == scheme)
            assert row['complete_honest'] == 'True'
            cost = float(row['execution_gas'])
            assert np.isfinite(cost) and cost > 0
            if scheme != 'das':
                old = next(r for r in frozen if int(r['n']) == n and r['scheme'] == scheme)
                assert cost == float(old['execution_gas'])
                assert float(row['io_gas']) == float(old['io_gas'])
            tier = next(t for t in (1, 2, 4, 8) if cost <= 9200*t)
            records.append({'n': n, 'scheme': LABELS[scheme],
                'execution_gas': cost, 'io_gas': float(row['io_gas']),
                'minimum_execution_budget_multiplier': tier,
                'standard_budget_success': row['normal_budget_success'],
                'measurement': 'complete official Aptos VM execution; no committed transaction'})
    fig, ax = plt.subplots(figsize=(3.45, 2.9))
    fig.subplots_adjust(left=.19, right=.79, bottom=.17, top=.86)
    for scheme in SCHEMES:
        group = [r for r in records if r['scheme'] == LABELS[scheme]]
        color, marker, line = STYLE[scheme]
        ax.plot(SIZES, [r['execution_gas'] for r in group], label=LABELS[scheme],
                color=color, marker=marker, ls=line, linewidth=1.25, markersize=3.7,
                zorder=3)
    for tier in (1, 2, 4, 8):
        budget = 9200*tier
        ax.axhline(budget, color='#888888', ls=':', linewidth=.7, zorder=1)
        ax.text(1.025, budget, f'{tier}' + r'$\times$' + f' {budget:,}',
                transform=ax.get_yaxis_transform(), color='#555555',
                fontsize=6.6, va='center', ha='left', clip_on=False)
    ax.set_ylim(0, 79000)
    ax.set_yticks([0, 20000, 40000, 60000])
    ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f'{int(value):,}'))
    ax.set_xscale('log', base=2)
    ax.set_xticks(SIZES, [str(n) for n in SIZES])
    ax.set_xlabel(r'Committee size $N$', labelpad=4)
    ax.set_ylabel('Execution gas', labelpad=4)
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', bbox_to_anchor=(.54, 1.015),
               ncol=2, frameon=False, fontsize=7, handlelength=2,
               columnspacing=1, labelspacing=.55)
    save(fig, 'aptos-full-verification', output)
    write_csv(output / 'aptos-full-verification-data.csv', records)
    (output / 'aptos-full-verification-provenance.json').write_text(json.dumps({
        'source': provenance(CHAIN_SOURCE), 'historical_WITS_Garg_source': provenance(FROZEN_CHAIN),
        'Das_native_pairing_source': provenance(DAS / 'chain-results/summary.csv'),
        'cases': len(records), 'samples_per_group': 1,
        'standard_execution_budget': 9200, 'budget_multipliers': [1, 2, 4, 8],
        'budget_lines_are_execution_ceiling_references': True,
        'staking_eligibility_or_mainnet_submission_tested': False,
        'operation_prices_unchanged': True,
        'new_benchmarks_run_by_renderer': False,
        'historical_WITS_Garg_costs_unchanged': True}, indent=2)+'\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--host-only', action='store_true')
    group.add_argument('--chain-only', action='store_true')
    group.add_argument('--active-only', action='store_true', help='render both active figures (default)')
    parser.add_argument('--output-dir', type=Path, default=HERE / 'figures')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    configure_style()
    if not args.chain_only:
        host_comparison(args.output_dir)
    if not args.host_only:
        chain_comparison(args.output_dir)
    print('Updated requested active figures; frozen observations unchanged.')


if __name__ == '__main__':
    main()
