#!/usr/bin/env python3

from collections import defaultdict

packages = set()
package_paths = defaultdict(set)
path_verdicts = defaultdict(dict)


def ingest(lore, label):
    global packages, package_paths, path_verdicts
    package_verdicts = defaultdict(set)

    for verdict, path in (line.split() for line in lore):
        package, _executable = path.split("/bin/")
        packages.add(package)
        package_verdicts[package].add((path, verdict))  # strip off the US
        path_verdicts[path][label] = verdict
        package_paths[package].add(path)

    return package_verdicts


with open("ubuntu") as ubuntu, open("macos") as macos:
    outcomes = {
        "can->cannot": 0,
        "can->might": 0,
        "cannot->can": 0,
        "cannot->might": 0,
        "might->can": 0,
        "might->cannot": 0,
    }

    ubuntu_package_verdicts = ingest(ubuntu, "ubuntu")
    macos_package_verdicts = ingest(macos, "macos")

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
