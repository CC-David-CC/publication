#!/usr/bin/env python3
"""Explicitly add account receipt checkpoints to a private official database."""
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'codiserver-server-v0.3.0')]
from steward.official_state_paths import validate_state
from steward.official_receipts import initialize

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--state',type=Path,required=True)
args=parser.parse_args()
state=args.state.absolute();validate_state(state);initialize(state/'official.sqlite')
print('Official receipt schema is ready')
