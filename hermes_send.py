"""Thin, installer-free entrypoint for the existing Hermes send CLI.

Run only with an explicitly configured, already-provisioned Hermes interpreter,
using -I -B. This deliberately imports neither hermes_bootstrap nor CLI main:
those entrypoints can repair/install their runtime and need writable HOME.
The upstream parser and handler retain credential resolution and delivery logic.
"""
import argparse


def main():
    from hermes_cli.send_cmd import register_send_subparser
    parser = argparse.ArgumentParser(description=__doc__)
    register_send_subparser(parser.add_subparsers(dest='command', required=True))
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
