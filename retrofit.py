#!/usr/bin/env python

# Yay python 3.x
from __future__ import print_function
from __future__ import generators
from __future__ import division
from __future__ import nested_scopes

import argparse
import os
import re
import shlex
import subprocess
import sys
import tempfile
import traceback


class Interfaces():
    """Manage /etc/network/interfaces file."""

    def __init__(self):
        # Open file
        handle = open("/etc/network/interfaces")

        # Make iterator of contents
        # l = line from read()
        line_buffer = [
            l.strip() for l in handle.read().splitlines() if l.strip()
        ]
        self.iterator = iter(line_buffer)

        # Close file
        handle.close()

        # Parsed directives
        self.directives = []

        # Do the needful
        self.parse()

    def parse(self):
        """Parse super- and sub-directives, and return nested results."""

        # For each directive
        for directive in self.iterator:
            # If we're on a super, start sub loop
            while directive.startswith(("iface", "mapping")):
                sup = None  # Clear super-directive
                subs = []   # Clear sub-directives

                # For each sub-directive
                for sub in self.iterator:
                    # If sub is actually a super
                    match_vars = (
                        "auto", "allow-", "iface", "mapping", "source"
                    )
                    if sub.startswith(match_vars):
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

    def save(self, simulate=False):
        """Pretty-print interface directives."""

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
        if simulate is True:
            msg = (
                'Changes to the interface files have not been made but you'
                ' can review the proposed changes here "{}"'.format(path)
            )
            print(msg)
        else:
            # Atomically replace interfaces file with temp file
            os.rename(path, "/etc/network/interfaces")

    def swapdirective(self, one, two):
        """Swap one directive with another."""

        # Walk directives
        for index, directive in enumerate(self.directives):
            # Swap directive if we found it
            if one in directive[0]:
                self.directives[index][0] = directive[0].replace(one, two)

    def adddirective(self, sup, subs=None, after=None, before=None):
        """Add directive."""

        def _get_index(directives):
            """Clear insertion point"""
            iface_insert = None
            # Walk directives
            for index, directive in enumerate(directives):
                # If directive already exists
                if directive[0] == sup and len(directive) > 2:
                    # Merge if subs are different
                    if len(set(directive[1]) - set(subs)):
                        _directives = list(set(directive[1])) + list(set(subs))
                        directives[index][1] = _directives

                    # Return because we don't need to insert
                    return
                # Save last insertion point if we found one
                elif directive[0] == after:
                    iface_insert = index + 1
                elif directive[0] == before:
                    iface_insert = index
            return iface_insert


        insert = _get_index(directives=self.directives)
        if insert is None:
            return

        # If before requested but not found, add at beginning
        if before:
            if not insert:
                insert = 0
        # If after specified but not found, add at end
        elif after:
            if not insert:
                insert = len(self.directives) + 1

        try:
            # Add directive and subs if any
            if subs:
                self.directives.insert(insert, [sup, subs])
            # Otherwise just add directive
            else:
                self.directives.insert(insert, [sup])
        except Exception:
            print(traceback.format_exc())
            msg = (
                'Failed when saving persistent network setup.'
                ' known args for operation = insert: {} sub: {}'
                ' subs: {} after: {} before: {}'.format(
                    insert, sup, subs, after, before
                )
            )
            print(msg)

    def addsubs(self, sup, subs):
        """Add sub-directives to super-directive."""

        # Walk directives
        for index, directive in enumerate(self.directives):
            # Append subs (flatly) if we found 'em
            if directive[0] == sup and len(directive) > 1:
                self.directives[index][1].extend(subs)

    def deletesubs(self, sup, subs):
        """Delete sub-directives from super-directive."""

        # Walk directives
        for index, directive in enumerate(self.directives):
            # Filter matching directive with subs
            if directive[0] == sup and len(directive) > 1:
                _directives = list(set(directive[1]) - set(subs))
                self.directives[index][1] = _directives

    def deletedirective(self, sup):
        """Delete directive and subs if any."""

        # Walk directives
        for index, directive in enumerate(self.directives):
            # Delete a matching directive
            if directive[0] == sup:
                del self.directives[index]


class Retrofit():
    """Parse interface and retrofit with OVS."""

    def __init__(self, args, exceptions=None):
        if exceptions is None:
            self.exceptions = []
        else:
            self.exceptions = exceptions

        self.action = args.action
        self.iface = args.iface
        self.linuxbridge = args.lb
        self.ovsbridge = args.ovs
        self.vethphy = "phy-" + self.linuxbridge
        self.vethovs = "ovs-" + self.linuxbridge
        self.force = args.force
        self.quiet = args.quiet
        self.verbose = args.verbose
        self.simulate = args.simulate
        self.no_persist = args.no_persist

        self.ips = None
        self.mac = None
        self.routes = None

    def shh(self, msg=""):
        """-q/--quiet message wrapper."""
        if self.quiet is True:
            print(msg)

    def call(self, cmd, simulate=False):
        """Wrap subprocess.check_output."""
        try:
            if self.verbose is True or self.simulate is True:
                print("Calling: {}".format(cmd))

            if simulate is False:
                output = subprocess.check_output(
                    shlex.split(cmd),
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                ).strip()

                if self.verbose is True and output:
                    print("-> Output: {}".format(output))

                return output
            else:
                return True

        except subprocess.CalledProcessError as e:
            print("Error calling:", cmd, file=sys.stderr)
            print("Exit code:", e.returncode, file=sys.stderr)
            print("Output:", e.output.strip(), file=sys.stderr)
            if self.force is True:
                raise Exception("call() error")
            else:
                print("* Ignoring by request.", file=sys.stderr)
                return ""

    def prepare(self, iface):
        """Gather information."""
        # TODO(evan): Check if interface is in a different bridge already
        # raise Exception("{} is in bridge {}, pass -f to force")

        self.shh()
        self.shh("** Gathering information for: '{}'".format(iface))

        # Get interface config
        dump = self.call("ip -o addr show {}".format(iface))

        # Store IP addresses
        self.ips = [
            ip for ip in re.findall("inet6?\s(\S+)", dump)
            if not ip.startswith("fe80")  # Exclude link-local
        ]

        self.shh("* IPs found: '{}'".format(", ".join(self.ips)))

        # Store MAC address
        self.mac = (lambda x: x.group(1) if x else x)
        self.mac = self.mac(re.search("link/ether\s(\S+)", dump))

        # Can has MAC?
        if not self.mac:
            raise Exception(
                "Interface '{}' has an unexpected or missing MAC address."
                " The universe may have ended, good luck!".format(iface))

        self.shh("* MAC found: '{}'".format(self.mac))

        # Store routes
        local_routes = self.call("ip route list".format(iface)).splitlines()

        # Exclude automatic routes
        self.routes = [
            " ".join(route.split()) for route in local_routes
            if iface in route and "kernel" not in route
        ]

        if len(self.routes):
            self.shh("* Routes found: {}".format(", ".join(self.routes)))

        self.shh()

    def startkeepalived(self):
        """Start keepalived service."""
        if "keepalived" in self.exceptions:
            return

        self.shh("* Starting keepalived")
        self.call("service keepalived start", simulate=self.simulate)

    def stopkeepalived(self):
        """Stop keepalived service."""
        if "keepalived" in self.exceptions:
            return

        self.shh("* Stopping keepalived")
        self.call("service keepalived stop", simulate=self.simulate)

    def modifykeepalived(self, one, two):
        """Keepalived config munger helper."""
        if "keepalived" in self.exceptions:
            return
        vrrp_dir = os.listdir("/etc/keepalived/conf.d")
        vrrp_files = [f for f in vrrp_dir if f.startswith("vrrp")]
        for vrrp_file in vrrp_files:
            self.shh(
                "* Replacing references to: '{}' with: '{}'"
                " in keepalived configs".format(one, two)
            )
            vrrp_path = os.path.join("/etc/keepalived/conf.d", vrrp_file)
            self.call(
                "sed -i 's/{}/{}/' {}".format(one, two, vrrp_path),
                simulate=self.simulate
            )

    def convertkeepalived(self):
        """Convert keepalived VRRP configs."""
        self.modifykeepalived(self.ovsbridge, self.linuxbridge)

    def revertkeepalived(self):
        """Revert keepalived VRRP configs."""
        self.modifykeepalived(self.linuxbridge, self.ovsbridge)

    def bootstrapkeepalived(self):
        """Bootstrap keepalived VRRP configs."""
        self.modifykeepalived(self.iface, self.linuxbridge)

    def createlinuxbridge(self):
        """Create linux bridge."""
        self.shh("* Creating bridge: '{}'".format(self.linuxbridge))
        self.call(
            "brctl addbr {}".format(self.linuxbridge),
            simulate=self.simulate
        )
        self.bringup([self.linuxbridge])

    def deletelinuxbridge(self):
        """Delete linux bridge."""
        self.bringdown([self.linuxbridge])
        self.shh("* Deleting linux bridge: '{}'".format(self.linuxbridge))

        self.call(
            "brctl delbr {}".format(self.linuxbridge), simulate=self.simulate
        )

    def createvethpair(self):
        """Create veth pair."""
        self.shh(
            "* Create veth pair: '{}'".format(
                ", ".join([self.vethphy, self.vethovs])
            )
        )
        if not self.simulate:
            cmd = "ip link add name {} type veth peer name {}".format(
                self.vethphy, self.vethovs
            )
            self.call(cmd, simulate=self.simulate)
            self.bringup([self.vethphy, self.vethovs])

    def deletevethpair(self):
        """Delete veth pair."""
        self.shh(
            "* Delete veth pair: '{}'".format(
                ", ".join([self.vethphy, self.vethovs])
            )
        )
        self.call(
            "ip link del {}".format(self.vethphy), simulate=self.simulate
        )

    def bringup(self, ifaces):
        """Bring interfaces up."""
        self.shh("* Bringing up interfaces: '{}'".format(", ".join(ifaces)))
        for iface in ifaces:
            self.call(
                "ip link set {} up".format(iface), simulate=self.simulate
            )

    def bringdown(self, ifaces):
        """Bring interfaces down."""
        self.shh("* Bringing down interfaces: '{}'".format(", ".join(ifaces)))
        for iface in ifaces:
            self.call(
                "ip link set {} down".format(iface), simulate=self.simulate
            )

    def bootstraplinuxbridge(self):
        """Bootstrap interfaces in linux bridge."""
        # Same as convert for now
        self.convertlinuxbridge()

    def convertlinuxbridge(self):
        """Add interfaces to linux bridge."""
        interfaces = ", ".join([self.iface, self.vethphy])
        self.shh(
            "* Adding interfaces: '{}' to: '{}'".format(
                interfaces, self.linuxbridge
            )
        )
        for iface in [self.iface, self.vethphy]:
            self.call(
                "brctl addif {} {}".format(self.linuxbridge, iface),
                simulate=self.simulate
            )

    def revertlinuxbridge(self):
        """Remove interfaces from linux bridge."""
        interfaces = ", ".join([self.iface, self.vethphy])
        self.shh(
            "* Removing interfaces: '{}' from: '{}'".format(
                interfaces, self.linuxbridge
            )
        )
        for iface in [self.iface, self.vethphy]:
            self.call(
                "brctl delif {} {}".format(self.linuxbridge, iface),
                simulate=self.simulate
            )

    def bootstrapovsbridge(self):
        """Bootstrap interfaces in OVS bridge."""
        self.shh(
            "* Adding interface: '{}' to: '{}'".format(
                self.vethovs,
                self.ovsbridge
            )
        )
        self.call(
            "ovs-vsctl add-port {} {}".format(self.ovsbridge, self.vethovs),
            simulate=self.simulate
        )

    def convertovsbridge(self):
        """Convert interfaces in OVS bridge."""
        self.shh(
            "* Removing interface: '{}' from: '{}'".format(
                self.iface,
                self.ovsbridge
            )
        )
        self.call(
            "ovs-vsctl del-port {} {}".format(self.ovsbridge, self.iface),
            simulate=self.simulate
        )
        self.bootstrapovsbridge()

    def revertovsbridge(self):
        """Revert interfaces in OVS bridge."""
        self.shh(
            "* Removing interface: '{}' from: '{}'".format(
                self.vethovs,
                self.ovsbridge
            )
        )

        self.call(
            "ovs-vsctl del-port {} {}".format(self.ovsbridge, self.vethovs),
            simulate=self.simulate
        )

        self.shh(
            "* Adding interface: '{}' to: '{}'".format(
                self.iface,
                self.ovsbridge
            )
        )
        self.call(
            "ovs-vsctl add-port {} {}".format(self.ovsbridge, self.iface),
            simulate=self.simulate
        )

    def setlinuxbridgemac(self):
        """Pin MAC address of bridge."""
        self.shh(
            "* Pin MAC address: '{}' to: '{}'".format(
                self.mac,
                self.linuxbridge
            )
        )

        self.call(
            "ip link set {} addr {}".format(self.linuxbridge, self.mac),
            simulate=self.simulate
        )

    def addips(self, iface):
        """Add IP addresses to specified interface."""
        self.shh(
            "* Add IPs: '{}' to: '{}'".format(
                ", ".join(self.ips),
                iface
            )
        )
        for ip in self.ips:
            self.call(
                "ip addr add dev {} {}".format(iface, ip),
                simulate=self.simulate
            )

    def fluships(self, iface):
        """Flush IP addresses from specified interface."""
        self.shh(
            "* Flush IPs: '{}' from: '{}'".format(
                ", ".join(self.ips),
                iface
            )
        )
        for ip in self.ips:
            self.call(
                "ip addr del {} dev {}".format(ip, iface),
                simulate=self.simulate
            )

    def flushinterfaceips(self):
        """Flush IP addresses from interface."""
        self.fluships(self.iface)

    def revertovsbridgeips(self):
        """Add IP addresses to OVS bridge."""
        self.addips(self.ovsbridge)

    def flushovsbridgeips(self):
        """Flush IP addresses from OVS bridge."""
        self.fluships(self.ovsbridge)

    def convertlinuxbridgeips(self):
        """Add IP addresses to linux bridge."""
        self.addips(self.linuxbridge)

    def bootstraplinuxbridgeips(self):
        """Add IP addresses to linux bridge."""
        # Same as convert for now
        self.convertlinuxbridgeips()

    def flushlinuxbridgeips(self):
        """Flush IP addresses from linux bridge."""
        self.fluships(self.linuxbridge)

    def modroutes(self, src, dst):
        """Modify route for src interface and add to dst interface."""
        routes = [
            route.replace(src, dst)
            for route in self.routes
        ]
        if len(routes):
            self.shh("* Add routes: '{}'".format(", ".join(routes)))
        for route in routes:
            self.call("ip route add {}".format(route), simulate=self.simulate)

    def convertovsbridgeroutes(self):
        """Convert routes in OVS bridge to linux bridge."""
        self.modroutes(self.ovsbridge, self.linuxbridge)

    def revertlinuxbridgeroutes(self):
        """Revert routes from linux bridge to OVS bridge."""
        self.modroutes(self.linuxbridge, self.ovsbridge)

    def bootstraplinuxbridgeroutes(self):
        """Bootstrap routes from interface to linux bridge."""
        self.modroutes(self.iface, self.linuxbridge)

    def convert(self):
        """Retrofit interfaces."""

        self.shh("*** Retrofitting interface: '{}'".format(self.iface))

        # Get current config
        self.prepare(self.ovsbridge)

        self.shh("** Starting retrofit")

        # Stop keepalived before we change things
        self.stopkeepalived()

        # Convert keepalived configs
        self.convertkeepalived()

        # Create linux bridge
        self.createlinuxbridge()

        # Set MAC of linux bridge
        self.setlinuxbridgemac()

        # Create veth pair
        self.createvethpair()

        # Flush OVS bridge
        self.flushovsbridgeips()

        # Convert OVS bridge interfaces
        self.convertovsbridge()

        # Convert linux bridge interfaces
        self.convertlinuxbridge()

        # Convert IPs to linux bridge
        self.convertlinuxbridgeips()

        # Convert routes from OVS bridge to linux bridge
        self.convertovsbridgeroutes()

        # Start keepalived again
        self.startkeepalived()

    def revert(self):
        """Revert interfaces."""

        self.shh("*** Reverting interface: '{}'".format(self.iface))

        # Get current config
        self.prepare(self.linuxbridge)

        self.shh("** Starting revert")

        # Stop keepalived before we change things
        self.stopkeepalived()

        # Revert keepalived configs
        self.revertkeepalived()

        # Flush linux bridge
        self.flushlinuxbridgeips()

        # Revert linux bridge interfaces
        self.revertlinuxbridge()

        # Delete linux bridge
        self.deletelinuxbridge()

        # Revert OVS bridge interfaces
        self.revertovsbridge()

        # Delete veth pair
        self.deletevethpair()

        # Revert IPs to OVS bridge
        self.revertovsbridgeips()

        # Revert routes from linux bridge to OVS bridge
        self.revertlinuxbridgeroutes()

        # Start keepalived again
        self.startkeepalived()

    def bootstrap(self):
        """Bootstrap interfaces."""

        self.shh("*** Bootstrapping interface: '{}'".format(self.iface))

        # Get current config
        self.prepare(self.iface)

        self.shh("** Starting bootstrap")

        # Stop keepalived before we change things
        self.stopkeepalived()

        # Bootstrap keepalived configs
        self.bootstrapkeepalived()

        # Create linux bridge
        self.createlinuxbridge()

        # Set MAC of linux bridge
        self.setlinuxbridgemac()

        # Create veth pair
        self.createvethpair()

        # Flush interface IPs
        self.flushinterfaceips()

        # Bootstrap linux bridge interfaces
        self.bootstraplinuxbridge()

        # Bootstrap OVS bridge interfaces
        self.bootstrapovsbridge()

        # Bootstrap IPs to linux bridge
        self.bootstraplinuxbridgeips()

        # Bootstrap routes from interface to linux bridge
        self.bootstraplinuxbridgeroutes()

        # Start keepalived again
        self.startkeepalived()

    def persist(self):
        """Persist/clean bridge/veth configuration."""

        # Create interface object
        interfaces = Interfaces()

        # Handle bootstrapping interface/converting OVS bridge to linux bridge
        if self.action in ["bootstrap", "convert"]:
            # Do specific swaps by action
            if self.action == "bootstrap":
                interfaces.swapdirective(self.iface, self.linuxbridge)

                # Add new auto directive
                interfaces.adddirective("auto {}".format(self.iface))
                # Add new iface directive with subs
                interfaces.adddirective(
                    "iface {} inet manual".format(self.iface),
                    [
                        "up ip link set $IFACE up",
                        "down ip link set $IFACE down"
                    ],
                    after="auto {}".format(self.iface)
                )

            elif self.action == "convert":
                interfaces.swapdirective(self.ovsbridge, self.linuxbridge)

            # Add auto directive for linux bridge
            interfaces.adddirective(
                "auto {}".format(self.linuxbridge),
                before="iface {} inet static".format(self.linuxbridge)
            )

            # Add sub-directives to linux-bridge
            interfaces.addsubs(
                "iface {} inet static".format(self.linuxbridge),
                [
                    "bridge_ports {} {}".format(self.iface, self.vethphy),
                    "pre-up ip link set dev $IFACE addr $(ip -o link show {} "
                    "| sed -nr 's|link/ether (\S+)|\\1|p') || true".format(
                        self.iface,
                    ),
                    "pre-up ip link add name {} "
                    "type veth peer name {} || true".format(
                        self.vethphy,
                        self.vethovs
                    ),
                    "pre-up ip link set {} up".format(self.vethphy),
                    "pre-up ip link set {} up".format(self.vethovs),
                    "post-down ip link del {} || true".format(self.vethphy)
                ]
            )

        # Handle reversion from linux bridge to OVS bridge
        elif self.action == "revert":
            # Delete sub-directives from linux bridge
            interfaces.deletesubs(
                "iface {} inet static".format(self.linuxbridge),
                [
                    "bridge_ports {} {}".format(self.iface, self.vethphy),
                    "pre-up ip link set dev $IFACE addr $(ip -o link show {} "
                    "| sed -nr 's|link/ether (\S+)|\\1|p') || true".format(
                        self.iface,
                    ),
                    "pre-up ip link add name {} "
                    "type veth peer name {} || true".format(
                        self.vethphy,
                        self.vethovs
                    ),
                    "pre-up ip link set {} up".format(self.vethphy),
                    "pre-up ip link set {} up".format(self.vethovs),
                    "post-down ip link del {} || true".format(self.vethphy)
                ]
            )

            # Delete auto directive for linux bridge
            interfaces.deletedirective("auto {}".format(self.linuxbridge))

            # Swap back to pre-convert config
            interfaces.swapdirective(self.linuxbridge, self.ovsbridge)

        interfaces.save(simulate=self.simulate)

    def retrofit(self):
        """Entry point dispatcher."""
        try:
            action = getattr(self, self.action)
        except AttributeError:
            print('Action "{}" was not found.'.format(self.action))
        except Exception:
            raise SystemExit(traceback.format_exc())
        else:
            action()
            if self.no_persist is False:
                self.persist()


def check(name, exception=False):
    """Check a binary."""
    try:
        devnull = open(os.devnull)
        subprocess.call(shlex.split(name), stdout=devnull, stderr=devnull)
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            # Add to exception list?
            if exception:
                return name

            msg = "Error calling {}; Is it installed?".format(name)
            raise Exception(msg)


def main():
    """Module entry point."""
    parser = argparse.ArgumentParser(
        description=("This tool will bootstrap, retrofit or revert an RPC"
                     " environment for single-NIC/multi-NIC configuration."),
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
        action="store_true",
        default=False
    )
    output.add_argument(
        "-q",
        "--quiet",
        help="Only output errors (to stderr)",
        action="store_true",
        default=False
    )

    user_input = parser.add_argument_group("user_input arguments")
    user_input.add_argument(
        "-i",
        "--iface",
        help="Interface to modify",
        type=str,
        required=True
    )
    user_input.add_argument(
        "-l",
        "--lb",
        help="Linux bridge to modify",
        type=str,
        required=True
    )
    user_input.add_argument(
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
        action="store_true",
        default=False,
    )
    action.add_argument(
        "--no-persist",
        help="Disable persistent changes",
        action="store_true",
        default=False
    )
    action.add_argument(
        "--simulate",
        help="Run no commands but simulate all actions",
        action="store_true",
        default=False
    )
    action.add_argument(
        "action",
        help="Action to perform",
        choices=["bootstrap", "convert", "revert"],
        type=str
    )
    args = parser.parse_args()

    try:
        exceptions = []
        for cmd in ['brctl', 'ip', 'sed', 'ovs-vsctl', 'service']:
            check(cmd)

        exceptions.append(check("keepalived", exception=True))

        retro = Retrofit(args, exceptions)
        retro.retrofit()

    except Exception:
        print(traceback.format_exc())
        raise SystemExit("Aborting due to exception")

if __name__ == "__main__":
    main()
