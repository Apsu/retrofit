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


class Interfaces():
    "Manage /etc/network/interfaces file"

    def __init__(self):
        # Open file
        handle = open("/etc/network/interfaces")

        # Make iterator of contents
        self.iterator = iter(
            [
                line.strip()
                for line in handle.read().splitlines()
                if line.strip()
            ]
        )
        # Close file
        handle.close()

        # Parsed directives
        self.directives = []

        # Do the needful
        self.parse()

    def parse(self):
        "Parse super- and sub-directives, and return nested results"

        # For each directive
        for directive in self.iterator:
            # If we're on a super, start sub loop
            while directive.startswith(("iface", "mapping")):
                sup = None  # Clear super-directive
                subs = []   # Clear sub-directives

                # For each sub-directive
                for sub in self.iterator:
                    # If sub is actually a super
                    if sub.startswith(
                        (
                            "auto",
                            "allow-",
                            "iface",
                            "mapping",
                            "source"
                        )
                    ):
                        sup = sub         # Set new super
                        break             # Exit sub loop
                    # Else it's just a sub, so add it
                    else:
                        subs.append(sub)

                # If we found subs, store them
                if subs:
                    self.directives.append([directive, subs])
                # Else just store directive
                else:
                    self.directives.append([directive])

                # If we didn't find a super, return
                if not sup:
                    return

                directive = sup  # Store super for next inner loop check

            # Not a super here so just add directive
            self.directives.append([directive])

        # End of iterator, return
        return

    def save(self):
        "Pretty-print interface directives"

        # Safely create temp file
        fd, path = tempfile.mkstemp()
        tmp = os.fdopen(fd, "w")

        # Write out changes
        for directive in self.directives:
            # Print directive
            print(directive[0], file=tmp)

            # If has subs
            if len(directive) > 1:
                # Print indented subs
                for sub in directive[1]:
                    print("    {}".format(sub), file=tmp)
            # If super, add a blank line for spacing
            if directive[0].startswith(("iface", "mapping")):
                print(file=tmp)

        tmp.close()
        # Atomically replace interfaces file with temp file
        os.rename(path, "/etc/network/interfaces")

    def swapDirective(self, one, two):
        "Swap one directive with another"

        # Walk directives
        for index, directive in enumerate(self.directives):
            # Swap directive if we found it
            if one in directive[0]:
                self.directives[index][0] = directive[0].replace(one, two)

    def addDirective(self, sup, subs=None, after=None, before=None):
        "Add directive"

        # Clear insertion point
        insert = None

        # Walk directives
        for index, directive in enumerate(self.directives):
            # If directive already exists
            if directive[0] == sup:
                # Merge if subs are different
                if len(set(directive[1]) - set(subs)):
                    self.directives[index][1] = list(
                        set(directive[1]) +
                        set(subs)
                    )
                # Return because we don't need to insert
                return
            # Save last insertion point if we found one
            elif directive[0] == after:
                insert = index + 1
            elif directive[0] == before:
                insert = index - 1

        # If before requested but not found, add at beginning
        if before:
            if not insert:
                insert = 0
        # If after specified but not found, add at end
        elif after:
            if not insert:
                insert = len(self.directives) + 1

        # Add directive and subs if any
        if subs:
            self.directives.insert(insert, [sup, subs])
        # Otherwise just add directive
        else:
            self.directives.insert(insert, [sup])

    def addSubs(self, sup, subs):
        "Add sub-directives to super-directive"

        # Walk directives
        for index, directive in enumerate(self.directives):
            # Append subs (flatly) if we found 'em
            if directive[0] == sup and len(directive) > 1:
                self.directives[index][1].extend(subs)

    def deleteSubs(self, sup, subs):
        "Delete sub-directives from super-directive"

        # Walk directives
        for index, directive in enumerate(self.directives):
            # Filter matching directive with subs
            if directive[0] == sup and len(directive) > 1:
                self.directives[index][1] = list(set(directive[1]) - set(subs))

    def deleteDirective(self, sup):
        "Delete directive and subs if any"

        # Walk directives
        for index, directive in enumerate(self.directives):
            # Delete a matching directive
            if directive[0] == sup:
                del self.directives[index]


class Retrofit():
    "Parse interface and retrofit with OVS"

    def __init__(self, args, exceptions=[]):
        self.exceptions = exceptions
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

    def call(self, cmd):
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
            if not self.force:
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
        dump = self.call("ip -o addr show {}".format(iface))

        # Store IP addresses
        self.ips = [
            ip
            for ip in re.findall("inet6?\s(\S+)", dump)
            if not ip.startswith("fe80")  # Exclude link-local
        ]

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

        if "keepalived" in self.exceptions:
            return

        self.shh("* Starting keepalived")
        self.call("service keepalived start")

    def stopKeepalived(self):
        "Stop keepalived service"

        if "keepalived" in self.exceptions:
            return

        self.shh("* Stopping keepalived")
        self.call("service keepalived stop")

    def modifyKeepalived(self, one, two):
        "Keepalived config munger helper"

        if "keepalived" in self.exceptions:
            return

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

    def bootstrapLinuxBridge(self):
        "Bootstrap interfaces in linux bridge"

        # Same as convert for now
        self.convertLinuxBridge()

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

    def addIPs(self, iface):
        "Add IP addresses to specified interface"

        self.shh(
            "* Add IPs: '{}' to: '{}'".format(
                ", ".join(self.ips),
                iface
            )
        )
        for ip in self.ips:
            self.call("ip addr add dev {} {}".format(iface, ip))

    def flushIPs(self, iface):
        "Flush IP addresses from specified interface"

        self.shh(
            "* Flush IPs: '{}' from: '{}'".format(
                ", ".join(self.ips),
                iface
            )
        )
        for ip in self.ips:
            self.call("ip addr del {} dev {}".format(ip, iface))

    def flushInterfaceIPs(self):
        "Flush IP addresses from interface"

        self.flushIPs(self.iface)

    def revertOVSBridgeIPs(self):
        "Add IP addresses to OVS bridge"

        self.addIPs(self.ovsBridge)

    def flushOVSBridgeIPs(self):
        "Flush IP addresses from OVS bridge"

        self.flushIPs(self.ovsBridge)

    def convertLinuxBridgeIPs(self):
        "Add IP addresses to linux bridge"

        self.addIPs(self.linuxBridge)

    def bootstrapLinuxBridgeIPs(self):
        "Add IP addresses to linux bridge"

        # Same as convert for now
        self.convertLinuxBridgeIPs()

    def flushLinuxBridgeIPs(self):
        "Flush IP addresses from linux bridge"

        self.flushIPs(self.linuxBridge)

    def modRoutes(self, src, dst):
        "Modify route for src interface and add to dst interface"

        routes = [
            route.replace(src, dst)
            for route in self.routes
        ]
        if len(routes):
            self.shh("* Add routes: '{}'".format(", ".join(routes)))
        for route in routes:
            self.call("ip route add {}".format(route))

    def convertOVSBridgeRoutes(self):
        "Convert routes in OVS bridge to linux bridge"

        self.modRoutes(self.ovsBridge, self.linuxBridge)

    def revertLinuxBridgeRoutes(self):
        "Revert routes from linux bridge to OVS bridge"

        self.modRoutes(self.linuxBridge, self.ovsBridge)

    def bootstrapLinuxBridgeRoutes(self):
        "Bootstrap routes from interface to linux bridge"

        self.modRoutes(self.iface, self.linuxBridge)

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

        # Convert IPs to linux bridge
        self.convertLinuxBridgeIPs()

        # Convert routes from OVS bridge to linux bridge
        self.convertOVSBridgeRoutes()

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

        # Revert IPs to OVS bridge
        self.revertOVSBridgeIPs()

        # Revert routes from linux bridge to OVS bridge
        self.revertLinuxBridgeRoutes()

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

        # Bootstrap keepalived configs
        self.bootstrapKeepalived()

        # Create linux bridge
        self.createLinuxBridge()

        # Set MAC of linux bridge
        self.setLinuxBridgeMAC()

        # Create veth pair
        self.createVethPair()

        # Flush interface IPs
        self.flushInterfaceIPs()

        # Bootstrap linux bridge interfaces
        self.bootstrapLinuxBridge()

        # Bootstrap OVS bridge interfaces
        self.bootstrapOVSBridge()

        # Bootstrap IPs to linux bridge
        self.bootstrapLinuxBridgeIPs()

        # Bootstrap routes from interface to linux bridge
        self.bootstrapLinuxBridgeRoutes()

        # Start keepalived again
        self.startKeepalived()

    def persist(self):
        "Persist/clean bridge/veth configuration"

        # Create interface object
        interfaces = Interfaces()

        # Handle bootstrapping interface/converting OVS bridge to linux bridge
        if self.action in ["bootstrap", "convert"]:
            # Do specific swaps by action
            if self.action == "bootstrap":
                interfaces.swapDirective(self.iface, self.linuxBridge)

                # Add new auto directive
                interfaces.addDirective("auto {}".format(self.iface))
                # Add new iface directive with subs
                interfaces.addDirective(
                    "iface {} inet manual".format(self.iface),
                    [
                        "up ip link set $IFACE up",
                        "down ip link set $IFACE down"
                    ],
                    after="auto {}".format(self.iface)
                )

            elif self.action == "convert":
                interfaces.swapDirective(self.ovsBridge, self.linuxBridge)

            # Add auto directive for linux bridge
            interfaces.addDirective(
                "auto {}".format(self.linuxBridge),
                before="iface {} inet static".format(self.linuxBridge)
            )

            # Add sub-directives to linux-bridge
            interfaces.addSubs(
                "iface {} inet static".format(self.linuxBridge),
                [
                    "bridge_ports {} {}".format(self.iface, self.vethPhy),
                    "pre-up ip link add name {} "
                    "type veth peer name {} || true".format(
                        self.vethPhy,
                        self.vethOvs
                    )
                ]
            )

        # Handle reversion from linux bridge to OVS bridge
        elif self.action == "revert":
            # Delete sub-directives from linux bridge
            interfaces.deleteSubs(
                "iface {} inet static".format(self.linuxBridge),
                [
                    "bridge_ports {} {}".format(self.iface, self.vethPhy),
                    "pre-up ip link add name {} "
                    "type veth peer name {} || true".format(
                        self.vethPhy,
                        self.vethOvs
                    )
                ]
            )

            # Delete auto directive for linux bridge
            interfaces.deleteDirective("auto {}".format(self.linuxBridge))

            # Swap back to pre-convert config
            interfaces.swapDirective(self.linuxBridge, self.ovsBridge)

        interfaces.save()

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

    # Check a binary
    def check(name, exception=False):
        try:
            devnull = open(os.devnull)
            subprocess.call(
                shlex.split(name),
                stdout=devnull,
                stderr=devnull
            )
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                # Add to exception list?
                if exception:
                    return name
                raise Exception(
                    "Error calling {}; might want to install it first.".format(
                        name
                    )
                )

    try:
        exceptions = []  # Flag these as missing but proceed
        check("brctl")
        check("ip")
        check("sed")
        check("ovs-vsctl")
        check("service")
        exceptions.append(check("keepalived", exception=True))

        retro = Retrofit(args, exceptions)
        retro.retrofit()

    except Exception as e:
        print("Aborting due to exception:", e, file=sys.stderr)

if __name__ == "__main__":
    main()
