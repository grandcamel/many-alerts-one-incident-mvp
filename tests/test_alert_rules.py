"""The related alert rules and the policy that groups them, read off the provisioning files.

The MVP's promise is that a fault fires several related Grafana alerts and one Run makes one
Incident. That rests on three things in `grafana/provisioning/alerting`, none of which needs a
running stack to check: every related rule carries the `incident_group` label, the notification
policy groups by that label alone on the spec's timings, and every rule's query names the demo
app's series and nothing else, so nothing but `docker compose stop traffic` can fire the group.
The opt-in checks in `tests/test_grafana.py` then ask the running Grafana for the same things.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPOSITORY = Path(__file__).resolve().parent.parent
PROVISIONING = REPOSITORY / "grafana" / "provisioning" / "alerting"

GROUP_LABEL = "incident_group"
"""The label on every related rule, and the one label the policy groups by (the spec's shared
interfaces)."""

GROUP_VALUE = "checkout-outage"
"""The demo's group. The Incident's Jira label is `grp-<this>`."""

JIRA_LABEL = re.compile(r"[a-z0-9-]+")
"""What a Jira group label may be made of, so the group's value must be too."""

GROUP_WAIT, GROUP_INTERVAL, REPEAT_INTERVAL = "30s", "1m", "3m"
"""The spec's demo timings."""

CONTACT_POINT = "demo-receiver"
"""The one contact point, unchanged by the MVP."""

DEMO_SERVICE = "rolldice"
"""The app every rule watches; its series carry `service_name="rolldice"`."""

TRAFFIC_ABSENCE_RULE = "rolldice-rate-zero"
"""Chapter one's rule, which `doctor` and `verify` look up by uid and which stays first."""

SUSTAINED_OUTAGE_RULE = "rolldice-outage-sustained"
"""The rule with the longest pending period, which fires last and exercises the update path."""

FEWEST_RULES, MOST_RULES = 3, 4
"""The spec asks for three to four related rules."""

FIELD_MAPPING_LABELS = {"severity", "service"}
"""What the Skill's field mapping reads off every alert."""

MAPPED_SEVERITIES = {"critical", "warning"}
"""The `severity` values the Skill maps to Sev-1 and Sev-2; anything else is a silent Sev-3."""

EVALUATION_INTERVAL = "10s"

PROMQL_WORDS = {"sum", "by", "rate", "increase", "instance"}
"""The functions, keywords and label names the rules' queries use. Any other identifier in a
query is a metric name and must carry a selector naming the demo app."""

SELECTOR = re.compile(r"\{([^}]*)\}")
RANGE = re.compile(r"\[\d+[smh]\]")
IDENTIFIER = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")


@pytest.fixture(scope="module")
def group() -> dict:
    groups = yaml.safe_load((PROVISIONING / "alert-rule.yaml").read_text())["groups"]
    assert len(groups) == 1, "one rule group, so one evaluation interval and one folder"
    return groups[0]


@pytest.fixture(scope="module")
def rules(group) -> list[dict]:
    return group["rules"]


@pytest.fixture(scope="module")
def policy() -> dict:
    policies = yaml.safe_load((PROVISIONING / "notification-policy.yaml").read_text())["policies"]
    assert len(policies) == 1
    return policies[0]


@pytest.fixture(scope="module")
def contact_point() -> dict:
    points = yaml.safe_load((PROVISIONING / "contact-point.yaml").read_text())["contactPoints"]
    assert len(points) == 1
    return points[0]


def test_there_are_three_to_four_related_rules(rules):
    assert FEWEST_RULES <= len(rules) <= MOST_RULES, [rule["title"] for rule in rules]


def test_every_related_rule_carries_the_group_label(rules):
    for rule in rules:
        assert rule["labels"].get(GROUP_LABEL) == GROUP_VALUE, rule["title"]


def test_the_group_value_makes_a_jira_label():
    assert JIRA_LABEL.fullmatch(GROUP_VALUE), f"grp-{GROUP_VALUE} would not be a Jira label"


def test_the_policy_groups_by_the_group_label_alone(policy):
    assert policy["group_by"] == [GROUP_LABEL], (
        "grouping by anything finer, alertname above all, sends each rule as its own group"
    )


def test_the_policy_runs_on_the_demo_timings(policy):
    assert policy["group_wait"] == GROUP_WAIT
    assert policy["group_interval"] == GROUP_INTERVAL
    assert policy["repeat_interval"] == REPEAT_INTERVAL


def test_the_contact_point_is_unchanged_and_the_policy_still_sends_to_it(policy, contact_point):
    assert contact_point["name"] == CONTACT_POINT
    assert policy["receiver"] == CONTACT_POINT
    assert not policy.get("routes"), "one route: everything goes to the Receiver"


def test_the_rules_query_only_the_demo_apps_series(rules):
    for rule in rules:
        for expr in prometheus_queries(rule):
            selectors = SELECTOR.findall(expr)
            assert selectors, f"{rule['title']}: {expr!r} selects no series"
            for selector in selectors:
                assert f'service_name="{DEMO_SERVICE}"' in selector, (
                    f"{rule['title']}: {{{selector}}} is not the demo app's series alone"
                )
            for name in metric_names(expr):
                assert f"{name}{{" in expr, (
                    f"{rule['title']}: {name} is queried without a selector"
                )


def test_every_rule_reads_one_prometheus_query_and_thresholds_it(rules):
    for rule in rules:
        assert len(prometheus_queries(rule)) == 1, rule["title"]
        condition = next(query for query in rule["data"] if query["refId"] == rule["condition"])
        assert condition["datasourceUid"] == "__expr__", rule["title"]
        assert condition["model"]["type"] == "threshold", rule["title"]


def test_the_traffic_absence_rule_stays_first_and_as_chapter_one_left_it(rules, group):
    """`doctor` and `verify` look it up by uid, and the offline doctor checks read the group's
    first rule; chapter one's fixtures are its recorded Notifications."""
    first = rules[0]

    assert first["uid"] == TRAFFIC_ABSENCE_RULE
    assert first["title"] == "rolldice request rate is zero"
    assert first["for"] == "30s"
    assert first["labels"]["severity"] == "critical"
    assert group["interval"] == EVALUATION_INTERVAL


def test_the_sustained_outage_rule_pends_longest(rules):
    """It fires after the others, so it joins the open Incident as a related alert: the
    update path, on purpose."""
    pending = {rule["uid"]: seconds(rule["for"]) for rule in rules}
    sustained = pending.pop(SUSTAINED_OUTAGE_RULE)

    assert sustained > max(pending.values()), pending
    assert sustained >= 2 * pending[TRAFFIC_ABSENCE_RULE]


def test_every_rule_labels_what_the_field_mapping_reads(rules):
    for rule in rules:
        assert set(rule["labels"]) >= FIELD_MAPPING_LABELS, rule["title"]
        assert rule["labels"]["service"] == DEMO_SERVICE, rule["title"]
        assert rule["labels"]["severity"] in MAPPED_SEVERITIES, rule["title"]


def test_no_data_and_a_query_error_stay_normal_on_every_rule(rules):
    """A rolldice that has not served a request yet is not an Incident, and a Notification
    about it would start a Run."""
    for rule in rules:
        assert rule["noDataState"] == "OK", rule["title"]
        assert rule["execErrState"] == "OK", rule["title"]
        assert rule["isPaused"] is False, rule["title"]


def test_uids_and_titles_are_distinct(rules):
    uids = [rule["uid"] for rule in rules]
    titles = [rule["title"] for rule in rules]

    assert len(set(uids)) == len(uids), uids
    assert len(set(titles)) == len(titles), titles


def test_every_rule_has_a_summary_and_a_description(rules):
    for rule in rules:
        assert rule["annotations"]["summary"].strip(), rule["title"]
        assert rule["annotations"]["description"].strip(), rule["title"]


def test_the_query_reader_finds_what_it_checks():
    """So the series check above cannot pass by finding nothing."""
    expr = 'sum by (instance) (rate(some_metric_total{service_name="other"}[20s])) + up'

    assert SELECTOR.findall(expr) == ['service_name="other"']
    assert metric_names(expr) == ["some_metric_total", "up"]


def prometheus_queries(rule: dict) -> list[str]:
    return [
        query["model"]["expr"] for query in rule["data"] if query["datasourceUid"] == "prometheus"
    ]


def metric_names(expr: str) -> list[str]:
    """Every identifier in a query that is not a PromQL word: the metrics it reads."""
    outside_selectors = RANGE.sub("", SELECTOR.sub("{}", expr))
    return [
        name for name in IDENTIFIER.findall(outside_selectors) if name not in PROMQL_WORDS
    ]


def seconds(duration: str) -> int:
    """A Grafana duration such as `30s` or `2m`, in seconds."""
    units = {"s": 1, "m": 60, "h": 3600}
    return int(duration[:-1]) * units[duration[-1]]
