# Copied from grafana/docker-otel-lgtm, examples/python/app.py
# (https://github.com/grafana/docker-otel-lgtm), Copyright Grafana Labs, and
# licensed under the Apache License, Version 2.0; a copy of the License is at
# http://www.apache.org/licenses/LICENSE-2.0. Modified to accept a per-request
# sides parameter for the optional diagnostic Fault; see NOTICE at the repository root.
"""Simple Flask app that rolls a dice."""

import logging
from random import randint

from flask import Flask, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route("/rolldice")
def roll_dice():
    """Rolls a dice and returns the result."""
    player = request.args.get("player", default=None, type=str)
    sides = int(request.args.get("sides", default="6"))
    result = str(roll(sides))
    if player:
        logger.warning("%s is rolling the dice: %s", player, result)
    else:
        logger.warning("Anonymous player is rolling the dice: %s", result)
    return result


def roll(sides=6):
    """Rolls a dice and returns the result."""
    return randint(1, sides)
