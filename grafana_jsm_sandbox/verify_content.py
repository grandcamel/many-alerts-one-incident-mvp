"""What `verify --mvp` holds an Incident's words to.

The lifecycle checks in `verify_mvp` prove that an Incident exists, carries its labels and
reaches its done status. A Run can do all of that and still write nothing a reader could use:
one rehearsal's cheapest model finished the lifecycle with the Description `Test`. These are
the content checks. Each takes the plain text of one field or comment and returns None when
it is well formed, or one sentence that names the field and what is missing from it, which
`verify_mvp` prints as `NOT VERIFIED: <stage> — <sentence>`. The stage is the one where the
fact first can be read:

    created    the Summary names the group and the firing count; the Description names
               each firing Alert and carries its generator URL
    grouped    the opening comment names each firing Alert with a value
    updated    an update comment lists the Alerts as New, Repeat and Resolved
    completed  the closing comment gives the duration, the Alert count and the Run count

The templates are the Skill's. These read them loosely where order, case, spacing and the way
a duration is spelled are not what a reader needs, so a Run may list its Alerts in any order,
and tightly on the facts: which Alerts, how many, and which list an Alert is in.

An Alert's text reaches the Incident through `incident-payload`'s `plain`, which swaps the
characters the permission boundary or the JSON would need escaped for look-alikes (`LOOK_ALIKES`
below is its table). Every comparison here applies the same `plain` to both sides, so an Alert
named `Disk "data" full` is found in a Description that reads `Disk ”data” full`.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

LOOK_ALIKES = str.maketrans({"'": "’", '"': "”", "\\": "⧵", "`": "ˋ", "$": "＄"})
"""`incident_payload.LOOK_ALIKES`, spelled again because this module cannot import it: it is the
verification lane's, and the tool is the Run's. `test_verify_mvp` pins the two equal on a tree
that holds both."""

MOST_LISTED = 4
"""How many missing items a sentence names before it says how many more there are."""

NUMBER = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[-+]?\d+)?"
"""A value as a Run copies it from `values.A`, lower case as `squash` leaves it."""

UNKNOWN = "unknown"
"""What `incident-payload` writes for an Alert whose `values.A` is missing."""

VALUE_AFTER_NAME = re.compile(rf"[^;]*?\bvalue\s*=\s*({NUMBER}|{UNKNOWN})")
"""What follows an Alert's name in the opening comment: anything but the next Alert's `;`, then
`value=` and the number, or `unknown` for an Alert that has none."""

UNIT = r"(?:h(?:ours?|rs?)?|m(?:in(?:ute)?s?)?|s(?:ec(?:ond)?s?)?)"
DURATION = rf"(?:\d+(?:\.\d+)?\s*{UNIT}(?![a-z])\s*)+"
"""`4m30s`, as the Skill writes it, and `4m 30s` or `4 minutes 30 seconds` as another Run may."""

LISTS = ("new", "repeat", "resolved")
"""The three lists of an update comment, in the Skill's order."""

SECTION = re.compile(r"(?<![\w-])(new|repeats?|resolved)\s*:")


@dataclass(frozen=True)
class Alert:
    """One Alert as far as a check can know it: the `fp-` label it gives the Incident, its name,
    and what the Report is to say about it. A name or an address the mode cannot learn is the
    label, or None, and the check then holds the text to nothing more than that."""

    label: str
    name: str
    generator_url: str | None = None
    value: str | None = None
    resolved: bool = False


@dataclass(frozen=True)
class Classified:
    """How a Notification's Alerts sort against what the Incident has already seen, and every
    other Alert of the group, so that a list naming an Alert this Notification lacks is caught."""

    firing: int | None = None
    new: tuple[Alert, ...] = ()
    repeat: tuple[Alert, ...] = ()
    resolved: tuple[Alert, ...] = ()
    others: tuple[Alert, ...] = ()


@dataclass(frozen=True)
class Update:
    """An update comment read back: the count it opens with, its three lists, the duration."""

    firing: int | None
    lists: dict[str, str]
    duration: str | None


def classify(
    alerts: Iterable[Alert], seen: Collection[str], others: Iterable[Alert] = ()
) -> Classified:
    """The Skill's rule: an Alert is resolved when the Notification says so, whatever else it
    would be; otherwise a repeat when its label is on the Incident already, else new."""
    alerts = tuple(alerts)
    resolved = tuple(alert for alert in alerts if alert.resolved)
    firing = tuple(alert for alert in alerts if not alert.resolved)
    here = {alert.label for alert in alerts}
    return Classified(
        firing=len(firing),
        new=tuple(alert for alert in firing if alert.label not in seen),
        repeat=tuple(alert for alert in firing if alert.label in seen),
        resolved=resolved,
        others=tuple(other for other in others if other.label not in here),
    )


def plain(text: str) -> str:
    """`incident_payload.plain`: `text` as one line with the characters `LOOK_ALIKES` names
    swapped, the way an Alert's words reach the Incident. Applying it twice changes nothing, so
    it is safe on words that went through the tool already."""
    kept = []
    for character in text:
        category = unicodedata.category(character)
        if category == "Cs":
            kept.append("\N{REPLACEMENT CHARACTER}")
        elif category in ("Cc", "Cf", "Zl", "Zp"):
            kept.append(" ")
        else:
            kept.append(character)
    return " ".join("".join(kept).split()).translate(LOOK_ALIKES)


def squash(text: str) -> str:
    """`text` as the checks compare it: as `plain` writes it, in one case. A straight quote a
    Run left as it was reads as the `’` the tool writes."""
    return plain(unicodedata.normalize("NFC", text)).casefold()


def shown(text: str, limit: int = 80) -> str:
    """`text` quoted for a sentence, on one line and cut short."""
    line = " ".join(text.split())
    return repr(line if len(line) <= limit else line[: limit - 1] + "…")


def listed(items: Sequence[str]) -> str:
    """The first few of `items`, and how many more there are."""
    shown_items = "; ".join(items[:MOST_LISTED])
    return shown_items + (
        f"; and {len(items) - MOST_LISTED} more" if len(items) > MOST_LISTED else ""
    )


def says(allowed: Collection[int]) -> str:
    """The counts a comment may give, as `4` or `1 to 4`."""
    low, high = min(allowed), max(allowed)
    return str(low) if low == high else f"{low} to {high}"


def names_in(text: str, names: Iterable[str]) -> set[str]:
    """The `names` that `text` names, longest first, each one spent once found, so that a name
    which begins another does not count where the longer one stands."""
    left = squash(text)
    found = set()
    for name in sorted(set(names), key=lambda name: len(squash(name)), reverse=True):
        needle = squash(name)
        if needle and needle in left:
            found.add(name)
            left = left.replace(needle, " ")
    return found


def has_label(text: str, label: str) -> bool:
    """Whether `text` holds the `fp-` label as a word, not as the start of a longer label."""
    return bool(re.search(rf"(?<![\w-]){re.escape(squash(label))}(?![\w-])", squash(text)))


def mentions(text: str, alert: Alert) -> bool:
    """Whether `text` names `alert`, by its name or by its `fp-` label."""
    return has_label(text, alert.label) or bool(names_in(text, [alert.name]))


def path_of(url: object) -> str | None:
    """A generator URL as Grafana's Alertmanager reports it, without the host: the Notification
    a Run reads carries the same address, but under the host Grafana was told it has."""
    if not isinstance(url, str) or not url:
        return None
    parts = urlsplit(url)
    path = parts.path + (f"?{parts.query}" if parts.query else "")
    return path if path.strip("/") else None


def same_number(found: str, wanted: str) -> bool:
    try:
        return float(found) == float(wanted)
    except ValueError:
        return found == wanted


# --- The Summary and the Description ---


def summary_problem(summary: str, group: str, firing: int | None) -> str | None:
    """The Summary reads `<group>: <n> alerts firing`: the group and the count, however else
    it is worded. `firing` None says the count is not known, and any count will do."""
    text = squash(summary)
    lacks = []
    if squash(group) not in text:
        lacks.append(f"the group {group}")
    count = r"\d+" if firing is None else rf"(?<!\d){firing}(?!\d)"
    if not re.search(rf"{count}\s+(?:alerts?\s+)?firing\b", text):
        lacks.append("the firing count" + ("" if firing is None else f" ({firing})"))
    if not lacks:
        return None
    form = f"{group}: {'<n>' if firing is None else firing} alerts firing"
    return f"Summary {shown(summary)} lacks {' and '.join(lacks)}: it reads like {form!r}"


def description_problem(text: str, alerts: Collection[Alert]) -> str | None:
    """The Description names each firing Alert and carries its generator URL."""
    named = names_in(text, (alert.name for alert in alerts))
    missing = []
    for alert in alerts:
        lacks = []
        if alert.name not in named:
            lacks.append("name")
        if alert.generator_url and alert.generator_url.translate(LOOK_ALIKES) not in text:
            lacks.append("generator URL")
        if lacks:
            missing.append(f"{alert.name} ({' and '.join(lacks)})")
    if not missing:
        return None
    return f"Description {shown(text)} is missing: {listed(missing)}"


# --- The comments ---


def opening_problem(text: str, alerts: Collection[Alert]) -> str | None:
    """The opening comment names each firing Alert with a value, `<alertname> value=<current>`.
    The value is held to the Alert's own only where it is known, as in a replay: a live
    Alert's value is whatever Grafana measured, and no check can say which, and an Alert
    with no `values.A` is `value=unknown`.

    Names are read longest first and each place one is found is spent, so a name that begins
    another is found only where it stands alone and takes the value that follows it there.
    Alerts that share a name are matched as a set: each of their values must be written once,
    in any order.
    """
    left = squash(text)
    by_name: dict[str, list[tuple[int, Alert]]] = {}
    for index, alert in enumerate(alerts):
        by_name.setdefault(squash(alert.name), []).append((index, alert))
    missing: list[tuple[int, str]] = []
    for needle in sorted(by_name, key=len, reverse=True):
        found = []
        written = False
        position = 0
        while needle and (at := left.find(needle, position)) >= 0:
            written = True
            end = at + len(needle)
            value = VALUE_AFTER_NAME.match(left, end)
            if value:
                found.append(value[1].rstrip("."))
                end = value.end()
            left = left[:at] + " " * (end - at) + left[end:]
            position = end
        if not written:
            missing += [(index, f"{alert.name} (name)") for index, alert in by_name[needle]]
            continue
        # Alerts whose value is known take the written value that equals it; an Alert whose
        # value is not known takes any that is left, so it cannot spend one a known Alert needs.
        valued = bool(found)
        for index, alert in sorted(by_name[needle], key=lambda pair: pair[1].value is None):
            if alert.value is None:
                if found:
                    found.pop(0)
                else:
                    missing.append((index, f"{alert.name} (value=<number>)"))
                continue
            match = next((value for value in found if same_number(value, alert.value)), None)
            if match is not None:
                found.remove(match)
            elif found:
                missing.append((index, f"{alert.name} (value={alert.value}, not {found[0]})"))
            elif valued:
                missing.append((index, f"{alert.name} (value={alert.value})"))
            else:
                missing.append((index, f"{alert.name} (value=<number>)"))
    if not missing:
        return None
    return (
        f"opening comment {shown(text)} is missing: {listed([said for _, said in sorted(missing)])}"
    )


def read_update(text: str) -> Update:
    """The count, the lists and the duration an update comment gives, whatever it does not."""
    squashed = squash(text)
    firing = re.search(r"update\W*(\d+)\s+(?:alerts?\s+)?firing", squashed)
    open_for = re.search(rf"open for\s+({DURATION})", squashed)
    marks = list(SECTION.finditer(squashed))
    stops = sorted([mark.start() for mark in marks] + ([open_for.start()] if open_for else []))
    lists: dict[str, str] = {}
    for mark in marks:
        end = next((stop for stop in stops if stop > mark.start()), len(squashed))
        name = "repeat" if mark[1].startswith("repeat") else mark[1]
        lists.setdefault(name, squashed[mark.end() : end].strip(" .;"))
    return Update(
        firing=int(firing[1]) if firing else None,
        lists=lists,
        duration=open_for[1].strip() if open_for else None,
    )


def update_problem(text: str, expected: Classified | None = None) -> str | None:
    """An update comment opens with how many Alerts fire, lists the Alerts as New, Repeat and
    Resolved, and says how long the Incident has been open. With `expected`, each list holds
    exactly the Alerts that sort there, in any order."""
    update = read_update(text)
    lacks = []
    if update.firing is None:
        lacks.append("`Update: <n> firing`")
    lacks += [f"`{name.capitalize()}:`" for name in LISTS if name not in update.lists]
    if update.duration is None:
        lacks.append("`Open for <duration>`")
    if lacks:
        return f"update comment {shown(text)} has no {', no '.join(lacks)}"
    if expected is None:
        return None
    wrong = []
    if expected.firing is not None and update.firing != expected.firing:
        wrong.append(f"`Update: {update.firing} firing`, not {expected.firing}")
    everyone = (*expected.new, *expected.repeat, *expected.resolved, *expected.others)
    for name in LISTS:
        wanted = {alert.name for alert in getattr(expected, name)}
        found = names_in(update.lists[name], (alert.name for alert in everyone))
        if found != wanted:
            wrong.append(
                f"{name.capitalize()} lists {', '.join(sorted(found)) or 'none'}, "
                f"not {', '.join(sorted(wanted)) or 'none'}"
            )
    if not wrong:
        return None
    return f"update comment {shown(text)} sorts the Alerts wrongly: {'; '.join(wrong)}"


def sorted_problem(
    texts: Sequence[str],
    seen: Collection[Alert],
    sustained: Alert | None,
    others: Collection[Alert] = (),
) -> str | None:
    """What an update comment's lists must satisfy when only Grafana's live state is known: an
    Alert the Incident had already seen is never New, and the sustained-outage Alert, when
    its comment is among `texts`, is New there. `others` are the Alerts the Incident has not
    seen, so that a name which begins another is not taken for it."""
    names = [alert.name for alert in (*seen, *others)]
    for text in texts:
        new = read_update(text).lists.get("new", "")
        found = names_in(new, names)
        for alert in seen:
            if alert.name in found or has_label(new, alert.label):
                return (
                    f"update comment {shown(text)} lists {alert.name} as New, but its "
                    f"{alert.label} label was on the Incident already"
                )
    if sustained is not None:
        naming = [text for text in texts if has_label(text, sustained.label)]
        for text in naming:
            if mentions(read_update(text).lists.get("new", ""), sustained):
                return None
        if naming:
            return (
                f"update comment {shown(naming[0])} does not list {sustained.name} "
                f"({sustained.label}) as New, though it joined the Incident there"
            )
    return None


def closing_problem(text: str, alerts: Collection[int], runs: Collection[int]) -> str | None:
    """The closing comment reads `Resolved after <duration>: every Alert in <group> is resolved
    (<n> Alerts, <m> Runs).` The Alert count must be among those the Incident supports;
    `runs` holds its exact lifecycle comment count, including the closing comment."""
    squashed = squash(text)
    lacks = []
    if not re.search(rf"resolved after\s+{DURATION}", squashed):
        lacks.append("no `Resolved after <duration>`")
    counts = re.search(r"\(\s*(\d+)\s+alerts?\s*,\s*(\d+)\s+runs?\s*\)", squashed)
    if not counts:
        lacks.append("no `(<n> Alerts, <m> Runs)`")
    else:
        if int(counts[1]) not in alerts:
            lacks.append(f"{counts[1]} Alerts, not {says(alerts)}")
        if int(counts[2]) not in runs:
            lacks.append(f"{counts[2]} Runs, not {says(runs)}")
    if not lacks:
        return None
    return f"closing comment {shown(text)} is malformed: {'; '.join(lacks)}"
