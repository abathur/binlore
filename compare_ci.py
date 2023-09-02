#!/usr/bin/env python3

import sys
import csv
import re
from collections import defaultdict

PATHSPLIT = re.compile(r"/bin/|/lib/|/libexec/")


class SuperSerial(csv.Dialect):
    """
    I'm using the unit separator for field separating but keeping \n
    for row/record separation for now. I realize that's a little
    inconsistent, but I feel like it's a good tradeoff between the
    chance that the serialization format has to handle an executable
    with the unit separator included, and keeping the format humane to
    write/script when where/needed.
    """

    delimiter = ":"
    escapechar = str("\x1f")  # https://en.wikipedia.org/wiki/Unit_separator
    quotechar = None
    doublequote = False
    skipinitialspace = False
    lineterminator = "\n"
    quoting = csv.QUOTE_NONE


csv.register_dialect("superserial", SuperSerial)


def read_execers(f):
    return csv.DictReader(
        f,
        [
            "verdict",  # can|cannot|might
            "executable",  # abspath
        ],
        dialect="superserial",
    )


def read_wrappers(f):
    return csv.DictReader(
        f,
        [
            "wrapper",  # abspath
            "wrapped",  # abspath
        ],
        dialect="superserial",
    )


packages = set()
package_paths = defaultdict(set)
path_verdicts = defaultdict(dict)


def ingest(exec_f, wrap_f, unhandled, label):
    execlore = read_execers(exec_f)
    wraplore = read_wrappers(wrap_f)

    global packages, package_paths, path_verdicts
    package_verdicts = defaultdict(set)
    wrapped = {row["wrapped"]: row["wrapper"] for row in wraplore}
    wrappers = wrapped.values()
    seen = set()

    for row in execlore:
        verdict = row["verdict"]
        path = row["executable"]

        if path in seen:
            raise Exception(
                "I've already seen this path, so I think that means it has two verdicts.",
                row,
            )
        else:
            seen.add(path)

        if verdict == "might" and path not in unhandled:
            raise Exception(
                "Let's see if we can enforce only yielding might when unhandled == true? %r %r %r"
                % (label, path, unhandled)
            )

        package, _executable = PATHSPLIT.split(path, maxsplit=1)
        packages.add(package)

        if path in wrapped:
            # we want the wrapped file's verdict, but we want the wrapper's path
            wrapper = wrapped[path]
            package_verdicts[package].add((wrapper, verdict))
            path_verdicts[wrapper][label] = verdict
            package_paths[package].add(wrapper)
        elif path in wrappers:
            # memory-hole the actual wrapper
            pass
        else:
            package_verdicts[package].add((path, verdict))
            path_verdicts[path][label] = verdict
            package_paths[package].add(path)

    return package_verdicts


with open("ubuntu-lore/execers") as ubuntu_execers, open(
    "ubuntu-lore/wrappers"
) as ubuntu_wrappers, open("ubuntu-lore/unhandled") as ubuntu_unhandled, open(
    "macos-lore/unhandled"
) as macos_unhandled, open(
    "macos-lore/execers"
) as macos_execers, open(
    "macos-lore/wrappers"
) as macos_wrappers:
    outcomes = {
        "can->cannot": 0,
        "can->might": 0,
        "cannot->can": 0,
        "cannot->might": 0,
        "might->can": 0,
        "might->cannot": 0,
    }

    unhandled = {
        "ubuntu": {x.strip() for x in ubuntu_unhandled.readlines()},
        "macos": {x.strip() for x in macos_unhandled.readlines()},
    }

    code = 0

    ubuntu_package_verdicts = ingest(
        ubuntu_execers, ubuntu_wrappers, unhandled["ubuntu"], "ubuntu"
    )
    macos_package_verdicts = ingest(
        macos_execers, macos_wrappers, unhandled["macos"], "macos"
    )

    for package in packages:
        diff = macos_package_verdicts[package].symmetric_difference(
            ubuntu_package_verdicts[package]
        )
        if not len(diff):
            print("  No diff in package:", package)
        else:
            print("!    package differs:", package)
            for path in package_paths[package]:
                verdicts = path_verdicts[path]

                if "macos" not in verdicts:
                    print(
                        "     macos=ABSENT ubuntu={ubuntu} path={:}".format(
                            path, **verdicts
                        )
                    )
                elif "ubuntu" not in verdicts:
                    print(
                        "     macos={macos} ubuntu=ABSENT path={:}".format(
                            path, **verdicts
                        )
                    )
                elif verdicts["macos"] == verdicts["ubuntu"]:
                    pass  # no diff; omit
                else:
                    print(
                        "     macos={macos} ubuntu={ubuntu} path={:}".format(
                            path, **verdicts
                        )
                    )
                    outcomes["{macos}->{ubuntu}".format(**verdicts)] += 1
        print("")

    print("\nSummary of macos -> ubuntu differences:")
    for outcome, count in outcomes.items():
        print("     {:6.6} -> {:6.6}  {:>6}".format(*outcome.split("->"), count))
        if count > 0:
            code = 1

sys.exit(code)
