#!/usr/bin/env python

# Yay python 3.x
from __future__ import print_function, generators, division, nested_scopes

import argparse
import os
import re
import shlex
import subprocess
import sys
import tempfile


class Retrofit():
    "Parse interface and retrofit with OVS"

    def __init__(self, args):
        self.action = args.action
        self.iface = args.iface
        self.linuxBridge = args.lb
        self.ovsBridge = args.ovs
        self.vethPhy = "phy-" + self.linuxBridge
        self.vethOvs = "ovs-" + self.linuxBridge
        self.force = args.force
        self.quiet = args.quiet
        self.verbose = args.verbose

    def shh(self, msg=""):
        "-q/--quiet message wrapper"
        if not self.quiet:
            print(msg)

    def call(self, cmd, ignore=False):
        "Wrap subprocess.check_output"
        try:
            if self.verbose:
                print("Calling: {}".format(cmd))

            output = subprocess.check_output(
                shlex.split(cmd),
                stderr=subprocess.STDOUT,
                universal_newlines=True
            ).strip()

            if self.verbose and len(output):
                print("-> Output: {}".format(output))

            return output
        except subprocess.CalledProcessError as e:
            print("Error calling:", cmd, file=sys.stderr)
            print("Exit code:", e.returncode, file=sys.stderr)
            print("Output:", e.output.strip(), file=sys.stderr)
            if not ignore:
                raise Exception("call() error")
            else:
                print("* Ignoring by request.", file=sys.stderr)
                return ""

    def prepare(self, iface):
        "Gather information"
        # TODO: Check if interface is in a different bridge already
        # raise Exception("{} is in bridge {}, pass -f to force")

        self.shh()
        self.shh("** Gathering information for: '{}'".format(iface))

        # Get interface config
        dump = self.call("ip -o addr show {}".format(iface), ignore=True)

        # Store IP addresses
        self.ips = [
            ip
            for ip in re.findall("inet6?\s(\S+)", dump)
            if not ip.startswith("fe80")  # Exclude link-local
        ]

        # Check we've got the right thing
        if not len(self.ips) and not self.force:
            raise Exception(
                "Interface '{}' has no IP addresses."
                " Pass -f to force anyway.".format(
                    iface
                )
            )

        self.shh("* IPs found: '{}'".format(", ".join(self.ips)))

        # Store MAC address
        self.mac = (lambda x: x.group(1) if x else x)(
            re.search(
                "link/ether\s(\S+)",
                dump
            )
        )

        # Can has MAC?
        if not self.mac:
            raise Exception(
                "Interface '{}' has an unexpected or missing MAC address."
                " The universe may have ended, good luck!".format(iface))

        self.shh("* MAC found: '{}'".format(self.mac))

        # Store routes
        self.routes = [
            " ".join(route.split())
            for route in self.call("ip route list".format(iface)).splitlines()
            # Exclude automatic routes
            if iface in route and "kernel" not in route
        ]

        if len(self.routes):
            self.shh("* Routes found: {}".format(", ".join(self.routes)))

        self.shh()

    def startKeepalived(self):
        "Start keepalived service"

        self.shh("* Starting keepalived")
        self.call("service keepalived start")

    def stopKeepalived(self):
        "Stop keepalived service"

        self.shh("* Stopping keepalived")
        self.call("service keepalived stop")

    def modifyKeepalived(self, one, two):
        for file in [
            file
            for file in os.listdir("/etc/keepalived/conf.d")
            if file.startswith("vrrp")
        ]:
            self.shh(
                "* Replacing references to: '{}' with: '{}'"
                " in keepalived configs".format(
                    one,
                    two
                )
            )
            self.call(
                "sed -i 's/{}/{}/' {}".format(
                    one,
                    two,
                    os.path.join("/etc/keepalived/conf.d", file)
                )
            )

    def convertKeepalived(self):
        "Convert keepalived VRRP configs"

        self.modifyKeepalived(self.ovsBridge, self.linuxBridge)

    def revertKeepalived(self):
        "Revert keepalived VRRP configs"

        self.modifyKeepalived(self.linuxBridge, self.ovsBridge)

    def bootstrapKeepalived(self):
        "Bootstrap keepalived VRRP configs"

        self.modifyKeepalived(self.iface, self.linuxBridge)

    def createLinuxBridge(self):
        "Create linux bridge"

        self.shh("* Creating bridge: '{}'".format(self.linuxBridge))
        self.call("brctl addbr {}".format(self.linuxBridge))
        self.bringUp([self.linuxBridge])

    def deleteLinuxBridge(self):
        "Delete linux bridge"

        self.bringDown([self.linuxBridge])
        self.shh("* Deleting linux bridge: '{}'".format(self.linuxBridge))
        self.call("brctl delbr {}".format(self.linuxBridge))

    def createVethPair(self):
        "Create veth pair"

        self.shh(
            "* Create veth pair: '{}'".format(
                ", ".join([self.vethPhy, self.vethOvs])
            )
        )
        self.call(
            "ip link add name {} type veth peer name {}".format(
                self.vethPhy,
                self.vethOvs
            )
        )
        self.bringUp([self.vethPhy, self.vethOvs])

    def deleteVethPair(self):
        "Delete veth pair"

        self.shh(
            "* Delete veth pair: '{}'".format(
                ", ".join([self.vethPhy, self.vethOvs])
            )
        )
        self.call("ip link del {}".format(self.vethPhy))

    def bringUp(self, ifaces):
        "Bring interfaces up"

        self.shh("* Bringing up interfaces: '{}'".format(", ".join(ifaces)))
        for iface in ifaces:
            self.call("ip link set {} up".format(iface))

    def bringDown(self, ifaces):
        "Bring interfaces down"

        self.shh(
            "* Bringing down interfaces: '{}'".format(", ".join(ifaces))
        )
        for iface in ifaces:
            self.call("ip link set {} down".format(iface))

    def convertLinuxBridge(self):
        "Add interfaces to linux bridge"

        self.shh(
            "* Adding interfaces: '{}' to: '{}'".format(
                ", ".join([self.iface, self.vethPhy]),
                self.linuxBridge
            )
        )
        for iface in [self.iface, self.vethPhy]:
            self.call("brctl addif {} {}".format(self.linuxBridge, iface))

    def revertLinuxBridge(self):
        "Remove interfaces from linux bridge"

        self.shh(
            "* Removing interfaces: '{}' from: '{}'".format(
                ", ".join([self.iface, self.vethPhy]),
                self.linuxBridge
            )
        )
        for iface in [self.iface, self.vethPhy]:
            self.call("brctl delif {} {}".format(self.linuxBridge, iface))

    def bootstrapOVSBridge(self):
        "Bootstrap interfaces in OVS bridge"

        self.shh(
            "* Adding interface: '{}' to: '{}'".format(
                self.vethOvs,
                self.ovsBridge
            )
        )
        self.call(
            "ovs-vsctl add-port {} {}".format(self.ovsBridge, self.vethOvs)
        )

    def convertOVSBridge(self):
        "Convert interfaces in OVS bridge"

        self.shh(
            "* Removing interface: '{}' from: '{}'".format(
                self.iface,
                self.ovsBridge
            )
        )
        self.call(
            "ovs-vsctl del-port {} {}".format(self.ovsBridge, self.iface)
        )
        self.bootstrapOVSBridge()

    def revertOVSBridge(self):
        "Revert interfaces in OVS bridge"

        self.shh(
            "* Removing interface: '{}' from: '{}'".format(
                self.vethOvs,
                self.ovsBridge
            )
        )
        self.call(
            "ovs-vsctl del-port {} {}".format(self.ovsBridge, self.vethOvs)
        )

        self.shh(
            "* Adding interface: '{}' to: '{}'".format(
                self.iface,
                self.ovsBridge
            )
        )
        self.call(
            "ovs-vsctl add-port {} {}".format(self.ovsBridge, self.iface)
        )

    def setLinuxBridgeMAC(self):
        "Pin MAC address of bridge"

        self.shh(
            "* Pin MAC address: '{}' to: '{}'".format(
                self.mac,
                self.linuxBridge
            )
        )
        self.call("ip link set {} addr {}".format(self.linuxBridge, self.mac))

    def addInterfaceIPs(self):
        "Add IP addresses to interface"

        self.shh(
            "* Add IPs: '{}' to: '{}'".format(
                ", ".join(self.ips),
                self.iface
            )
        )
        for ip in self.ips:
            self.call("ip addr add dev {} {}".format(self.iface, ip))

    def flushInterfaceIPs(self):
        "Flush IP addresses from interface"

        self.shh(
            "* Flush IPs: '{}' from: '{}'".format(
                ", ".join(self.ips),
                self.iface
            )
        )
        for ip in self.ips:
            self.call("ip addr del {} dev {}".format(ip, self.iface))

    def addOVSBridgeIPs(self):
        "Add IP addresses to OVS bridge"

        self.shh(
            "* Add IPs: '{}' to: '{}'".format(
                ", ".join(self.ips),
                self.ovsBridge
            )
        )
        for ip in self.ips:
            self.call("ip addr add dev {} {}".format(self.ovsBridge, ip))

    def flushOVSBridgeIPs(self):
        "Flush IP addresses from interface"

        self.shh(
            "* Flush IPs: '{}' from: '{}'".format(
                ", ".join(self.ips),
                self.ovsBridge
            )
        )
        for ip in self.ips:
            self.call("ip addr del {} dev {}".format(ip, self.ovsBridge))

    def addOVSBridgeRoutes(self):
        "Add routes to OVS bridge"

        routes = [
            route.replace(self.iface, self.OVSBridge)
            for route in self.routes
        ]
        if len(routes):
            self.shh("* Add routes: '{}'".format(", ".join(routes)))
        for route in routes:
            self.call("ip route add {}".format(route))

    def addLinuxBridgeIPs(self):
        "Add IP addresses to linux bridge"

        self.shh(
            "* Add IPs: '{}' to: '{}'".format(
                ", ".join(self.ips),
                self.linuxBridge
            )
        )
        for ip in self.ips:
            self.call("ip addr add dev {} {}".format(self.linuxBridge, ip))

    def flushLinuxBridgeIPs(self):
        "Flush IP addresses from linux bridge"

        self.shh(
            "* Flush IPs: '{}' from: '{}'".format(
                ", ".join(self.ips),
                self.linuxBridge
            )
        )
        for ip in self.ips:
            self.call("ip addr del {} dev {}".format(ip, self.linuxBridge))

    def addLinuxBridgeRoutes(self):
        "Add routes to linux bridge"

        routes = [
            route.replace(self.iface, self.linuxBridge)
            for route in self.routes
        ]
        if len(routes):
            self.shh("* Add routes: '{}'".format(", ".join(routes)))
        for route in routes:
            self.call("ip route add {}".format(route))

    def convert(self):
        "Retrofit interfaces"

        self.shh("*** Retrofitting interface: '{}'".format(self.iface))

        # Get current config
        self.prepare(self.ovsBridge)

        self.shh("** Starting retrofit")

        # Stop keepalived before we change things
        self.stopKeepalived()

        # Convert keepalived configs
        self.convertKeepalived()

        # Create linux bridge
        self.createLinuxBridge()

        # Set MAC of linux bridge
        self.setLinuxBridgeMAC()

        # Create veth pair
        self.createVethPair()

        # Flush OVS bridge
        self.flushOVSBridgeIPs()

        # Convert OVS bridge interfaces
        self.convertOVSBridge()

        # Convert linux bridge interfaces
        self.convertLinuxBridge()

        # Add IPs to linux bridge
        self.addLinuxBridgeIPs()

        # Add routes to linux bridge
        self.addLinuxBridgeRoutes()

        # Start keepalived again
        self.startKeepalived()

    def revert(self):
        "Revert interfaces"

        self.shh("*** Reverting interface: '{}'".format(self.iface))

        # Get current config
        self.prepare(self.linuxBridge)

        self.shh("** Starting revert")

        # Stop keepalived before we change things
        self.stopKeepalived()

        # Revert keepalived configs
        self.revertKeepalived()

        # Flush linux bridge
        self.flushLinuxBridgeIPs()

        # Revert linux bridge interfaces
        self.revertLinuxBridge()

        # Delete linux bridge
        self.deleteLinuxBridge()

        # Revert OVS bridge interfaces
        self.revertOVSBridge()

        # Delete veth pair
        self.deleteVethPair()

        # Add IPs to OVS bridge
        self.addOVSBridgeIPs()

        # Add routes to OVS bridge
        self.addOVSBridgeRoutes()

        # Start keepalived again
        self.startKeepalived()

    def bootstrap(self):
        "Bootstrap interfaces"

        self.shh("*** Bootstrapping interface: '{}'".format(self.iface))

        # Get current config
        self.prepare(self.iface)

        self.shh("** Starting bootstrap")

        # Stop keepalived before we change things
        self.stopKeepalived()

        # Convert keepalived configs
        self.convertKeepalived()

        # Create linux bridge
        self.createLinuxBridge()

        # Set MAC of linux bridge
        self.setLinuxBridgeMAC()

        # Create veth pair
        self.createVethPair()

        # Flush interface IPs
        self.flushInterfaceIPs()

        # Bootstrap linux bridge interfaces
        self.convertLinuxBridge()

        # Bootstrap OVS bridge interfaces
        self.bootstrapOVSBridge()

        # Add IPs to linux bridge
        self.addLinuxBridgeIPs()

        # Add routes to linux bridge
        self.addLinuxBridgeRoutes()

        # Start keepalived again
        self.startKeepalived()

    def persist(self):
        "Persist/clean bridge/veth configuration"
        if self.action in ["bootstrap", "convert"]:
            # TODO: Detect platform

            # Ubuntu
            # TODO:
            # - Parse /etc/network/interfaces
            fd = open("/etc/network/interfaces", "r")

            # - Replace self.iface with self.linuxBridge
            #   - Add "bridge_ports self.iface phy-self.iface"
            # - Add auto self.iface
            # - Add iface self.iface inet manual
            #   - Add up ip link set $IFACE up
            #   - Add down ip link set $IFACE down

            fd.close()
            # Safely create temp file
            #tmp, path = tempfile.mkstemp()
            # - Write out changes

            # - Write /etc/network/if-{pre-up,post-down}.d/ file
            #   - Will create/up or down/delete veth pair
        elif self.action == "revert":
            pass

    def retrofit(self):
        "Entry point dispatcher"
        if self.action == "bootstrap":
            self.bootstrap()
        elif self.action == "convert":
            self.convert()
        elif self.action == "revert":
            self.revert()

        self.persist()


def main():
    "Module entry point"
    parser = argparse.ArgumentParser(
        description="This tool will bootstrap, retrofit or revert an RPC"
        " environment for single-NIC/multi-NIC configuration.",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog,
            max_help_position=80
        )
    )

    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "-v",
        "--verbose",
        help="Verbose output of steps taken",
        action="store_true"
    )
    output.add_argument(
        "-q",
        "--quiet",
        help="Only output errors (to stderr)",
        action="store_true"
    )

    input = parser.add_argument_group("input arguments")
    input.add_argument(
        "-i",
        "--iface",
        help="Interface to modify",
        type=str,
        required=True
    )
    input.add_argument(
        "-l",
        "--lb",
        help="Linux bridge to modify",
        type=str,
        required=True
    )
    input.add_argument(
        "-o",
        "--ovs",
        help="OVS bridge to modify",
        type=str,
        required=True
    )

    action = parser.add_argument_group("actions")
    action.add_argument(
        "-f",
        "--force",
        help="Forcibly reconfigure interface",
        action="store_true"
    )
    action.add_argument(
        "action",
        help="Action to perform",
        choices=["bootstrap", "convert", "revert"],
        type=str
    )
    args = parser.parse_args()

    try:
        retro = Retrofit(args)
        retro.retrofit()

    except Exception as e:
        print("Aborting due to exception:", e, file=sys.stderr)

if __name__ == "__main__":
    main()
