#!/usr/bin/env python

# Yay python 3.x
from __future__ import print_function, generators, division, nested_scopes, with_statement

import argparse
import ConfigParser
import os
import re
import shlex
import subprocess
import sys


class Retrofit():
  "Parse interface and retrofit with OVS"
  def __init__(self, args):
    self.iface = args.iface
    self.linuxBridge = args.lb
    self.ovsBridge = args.ovs
    self.force = args.force
    self.quiet = args.quiet
    self.verbose = args.verbose

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
      print("Output:", e.output, file=sys.stderr)
      if not ignore:
        raise Exception("call() error")
      else:
        print("Ignoring by request.", file=sys.stderr)
        return ""

  def prepare(self, iface):
    "Gather information"
    # TODO: Check if interface is in a different bridge already
    # raise Exception("{} is in bridge {}, pass -f to force")

    if not self.quiet:
      print()
      print("** Gathering information for: '{}' **".format(iface))

    # Get interface config
    dump = self.call("ip -o addr show {}".format(iface), ignore=True)

    # Store IP addresses
    self.ips = [
      ip
      for ip in re.findall("inet6?\s(\S+)", dump)
      if not ip.startswith("fe80") # Exclude link-local
    ]

    # Check we've got the right thing
    if not len(self.ips) and not self.force:
      raise Exception("Interface '{}' has no IP addresses. Pass -f to force anyway.".format(iface))

    if not self.quiet:
      print("* IPs found: '{}' *".format(", ".join(self.ips)))

    # Store MAC address
    self.mac = (lambda x: x.group(1) if x else x)(re.search("link/ether\s(\S+)", dump))

    # Can has MAC?
    if not self.mac:
      raise Exception("Interface '{}' has an unexpected or missing MAC address. The universe may have ended, good luck!".format(iface))

    if not self.quiet:
      print("* MAC found: '{}' *".format(self.mac))

    # Store routes
    self.routes = [
      " ".join(route.split())
      for route in self.call("ip route list".format(iface)).splitlines()
      if iface in route and "kernel" not in route # Exclude automatic routes
    ]

    if not self.quiet and len(self.routes):
      print("* Routes found: {} *".format(", ".join(self.routes)))

  def retrofit(self):
    "Retrofit interfaces"

    if not self.quiet:
      print("*** Retrofitting interface: '{}' ***".format(self.iface))

    # Get current config
    self.prepare(self.ovsBridge)

    if not self.quiet:
      print()
      print("** Starting retrofit **")
      print("* Creating bridge and veth pair *")

    # Create linux bridge
    self.call("brctl addbr {}".format(self.linuxBridge), ignore=True)

    # Create veth pair
    self.call(
      "ip link add name phy-{0} type veth peer name ovs-{0}".format(
        self.linuxBridge),
      ignore=True
    )

    # Bring them up
    for dev in [self.iface, self.linuxBridge, "phy-" + self.linuxBridge, "ovs-" + self.linuxBridge]:
      self.call("ip link set {} up".format(dev))

    if not self.quiet:
      print("* Stopping keepalived to reconfigure it *")

    # Stop keepalived before we change things
    self.call("service keepalived stop")

    if not self.quiet:
      print("* Replacing references to: '{}' with: '{}' in keepalived configs *".format(self.ovsBridge, self.linuxBridge))

    # Modify configs to use the linux bridge
    for file in [
      file
      for file in os.listdir("/etc/keepalived/conf.d")
      if file.startswith("vrrp")
    ]:
      self.call(
        "sed -i 's/{}/{}/' {}".format(
          self.ovsBridge,
          self.linuxBridge,
          os.path.join("/etc/keepalived/conf.d", file)
        )
      )

    if not self.quiet:
      print("* Remove IPs and interface: '{}' from: '{}' *".format(self.iface, self.ovsBridge))

    # Flush IPs from OVS bridge
    self.call("ip addr flush {}".format(self.ovsBridge))

    # Remove interface from OVS bridge
    self.call(
      "ovs-vsctl del-port {} {}".format(
        self.ovsBridge,
        self.iface),
      ignore=True
    )

    # Bring down OVS interface
    self.call("ip link set {} down".format(self.ovsBridge))

    if not self.quiet:
      print("* Add interface: '{}' and veth: '{}' to: '{}'".format(self.iface, "phy-" + self.linuxBridge, self.linuxBridge))

    # Add interfaces to linux bridge
    for dev in [self.iface, "phy-" + self.linuxBridge]:
      self.call("brctl addif {} {}".format(self.linuxBridge, dev), ignore=True)

    if not self.quiet:
      print("* Pin MAC address: '{}' to: '{}'".format(self.mac, self.linuxBridge))

    # Set MAC address of linux bridge
    self.call("ip link set {} addr {}".format(self.linuxBridge, self.mac))

    if not self.quiet:
      print("* Add veth: '{}' to: '{}'".format("ovs-" + self.linuxBridge, self.ovsBridge))

    # Add other veth interface to OVS bridge
    self.call(
      "ovs-vsctl add-port {} {}".format(
        self.ovsBridge,
        "ovs-" + self.linuxBridge
      ),
      ignore=True
    )

    if not self.quiet:
      print("* Add IPs: '{}' to: '{}'".format(", ".join(self.ips), self.linuxBridge))

    # Add IPs to new linux bridge
    for ip in self.ips:
      self.call(
        "ip addr add dev {} {}".format(
          self.linuxBridge,
          ip
        ),
        ignore=True
      )

    # Modify route devices
    self.routes = [
      route.replace(self.ovsBridge, self.linuxBridge)
      for route in self.routes
    ]

    if not self.quiet and len(self.routes):
      print("* Add routes: '{}' *".format(", ".join(self.routes)))

    # Add routes
    for route in self.routes:
      self.call("ip route add {}".format(route))

    if not self.quiet:
      print("* Start keepalived *")

    # Start keepalived again
    self.call("service keepalived start")

  def revert(self):
    "Revert interfaces"

    if not self.quiet:
      print("*** Reverting interface: '{}' ***".format(self.iface))

    # Get current config
    self.prepare(self.linuxBridge)

    if not self.quiet:
      print()
      print("** Starting revert **")
      print("* Stopping keepalived to reconfigure it *")

    # Stop keepalived before we change things
    self.call("service keepalived stop")

    if not self.quiet:
      print("* Replacing references to: '{}' with: '{}' in keepalived configs *".format(self.linuxBridge, self.ovsBridge))

    # Modify configs to use the linux bridge
    for file in [
      file
      for file in os.listdir("/etc/keepalived/conf.d")
      if file.startswith("vrrp")
    ]:
      self.call(
        "sed -i 's/{}/{}/' {}".format(
          self.linuxBridge,
          self.ovsBridge,
          os.path.join("/etc/keepalived/conf.d", file)
        )
      )

    if not self.quiet:
      print("* Remove IPs, interface: '{}' and veth: '{}' from: '{}' *".format(self.iface, "phy-" + self.linuxBridge, self.linuxBridge))

    # Flush IPs from linux bridge
    self.call("ip addr flush {}".format(self.linuxBridge))

    # Remove interfaces from linux bridge
    for dev in [self.iface, "phy-" + self.linuxBridge]:
      self.call("brctl delif {} {}".format(self.linuxBridge, dev), ignore=True)

    if not self.quiet:
      print("* Remove veth: '{}' from: '{}'".format("ovs-" + self.linuxBridge, self.ovsBridge))

    # Remove other veth interface from OVS bridge
    self.call(
      "ovs-vsctl del-port {} {}".format(
        self.ovsBridge,
        "ovs-" + self.linuxBridge
      ),
      ignore=True
    )

    if not self.quiet:
      print("* Delete veth pair *")

    # Delete veth pair
    self.call(
      "ip link delete phy-{0}".format(
        self.linuxBridge),
      ignore=True
    )

    if not self.quiet:
      print("* Delete linux bridge: '{}' *".format(self.linuxBridge))

    # Set bridge down
    self.call("ip link set {} down".format(self.linuxBridge))

    # Delete linux bridge
    self.call("brctl delbr {}".format(self.linuxBridge), ignore=True)

    if not self.quiet:
      print("* Add interface: '{}' to: '{}'".format(self.iface, self.ovsBridge))

    # Add interface to OVS bridge
    self.call(
      "ovs-vsctl add-port {} {}".format(
        self.ovsBridge,
        self.iface),
      ignore=True
    )

    if not self.quiet:
      print("* Add IPs: '{}' to: '{}'".format(", ".join(self.ips), self.ovsBridge))

    # Bring up OVS interface
    self.call("ip link set {} up".format(self.ovsBridge))

    # Add IPs to OVS interface
    for ip in self.ips:
      self.call(
        "ip addr add dev {} {}".format(
          self.ovsBridge,
          ip
        ),
        ignore=True
      )

    # Modify route devices
    self.routes = [
      route.replace(self.linuxBridge, self.ovsBridge)
      for route in self.routes
    ]

    if not self.quiet and len(self.routes):
      print("* Add routes: '{}' *".format(", ".join(self.routes)))

    # Add routes
    for route in self.routes:
      self.call("ip route add {}".format(route))

    if not self.quiet:
      print("* Start keepalived *")

    # Start keepalived again
    self.call("service keepalived start")


  def bootstrap(self):
    "Bootstrap interfaces"

    if not self.quiet:
      print("*** Bootstrapping interface: '{}' ***".format(self.iface))

    # Get current config
    self.prepare(self.iface)

    if not self.quiet:
      print()
      print("** Starting retrofit **")
      print("* Creating bridge and veth pair *")

    # Create linux bridge
    self.call("brctl addbr {}".format(self.linuxBridge), ignore=True)

    # Create veth pair
    self.call(
      "ip link add name phy-{0} type veth peer name ovs-{0}".format(
        self.linuxBridge),
      ignore=True
    )

    # Bring them up
    for dev in [self.iface, self.linuxBridge, "phy-" + self.linuxBridge, "ovs-" + self.linuxBridge]:
      self.call("ip link set {} up".format(dev))

    if not self.quiet:
      print("* Stopping keepalived to reconfigure it *")

    # Stop keepalived before we change things
    self.call("service keepalived stop")

    if not self.quiet:
      print("* Replacing references to: '{}' with: '{}' in keepalived configs *".format(self.iface, self.linuxBridge))

    # Modify configs to use the linux bridge
    for file in [
      file
      for file in os.listdir("/etc/keepalived/conf.d")
      if file.startswith("vrrp")
    ]:
      self.call(
        "sed -i 's/{}/{}/' {}".format(
          self.iface,
          self.linuxBridge,
          os.path.join("/etc/keepalived/conf.d", file)
        )
      )

    if not self.quiet:
      print("* Remove IPs from: '{}' *".format(self.iface))

    # Flush IPs from OVS bridge
    self.call("ip addr flush {}".format(self.iface))

    if not self.quiet:
      print("* Add interface: '{}' and veth: '{}' to: '{}'".format(self.iface, "phy-" + self.linuxBridge, self.linuxBridge))

    # Add interfaces to linux bridge
    for dev in [self.iface, "phy-" + self.linuxBridge]:
      self.call("brctl addif {} {}".format(self.linuxBridge, dev), ignore=True)

    if not self.quiet:
      print("* Pin MAC address: '{}' to: '{}'".format(self.mac, self.linuxBridge))

    # Set MAC address of linux bridge
    self.call("ip link set {} addr {}".format(self.linuxBridge, self.mac))

    if not self.quiet:
      print("* Add veth: '{}' to: '{}'".format("ovs-" + self.linuxBridge, self.ovsBridge))

    # Add other veth interface to OVS bridge
    self.call(
      "ovs-vsctl add-port {} {}".format(
        self.ovsBridge,
        "ovs-" + self.linuxBridge
      ),
      ignore=True
    )

    if not self.quiet:
      print("* Add IPs: '{}' to: '{}'".format(", ".join(self.ips), self.linuxBridge))

    # Add IPs to new linux bridge
    for ip in self.ips:
      self.call(
        "ip addr add dev {} {}".format(
          self.linuxBridge,
          ip
        ),
        ignore=True
      )

    # Modify route devices
    self.routes = [
      route.replace(self.iface, self.linuxBridge)
      for route in self.routes
    ]

    if not self.quiet and len(self.routes):
      print("* Add routes: '{}' *".format(", ".join(self.routes)))

    # Add routes
    for route in self.routes:
      self.call("ip route add {}".format(route))

    if not self.quiet:
      print("* Start keepalived *")

    # Start keepalived again
    self.call("service keepalived start")



def main():
  parser = argparse.ArgumentParser(description="This tool will bootstrap, retrofit or revert an RPC environment for single-NIC/multi-NIC configuration.",
                                   formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80))

  output = parser.add_mutually_exclusive_group()
  output.add_argument("-v", "--verbose", help="Verbose output of steps taken", action="store_true")
  output.add_argument("-q", "--quiet", help="Only output errors (to stderr)", action="store_true")

  input = parser.add_argument_group("input arguments")
  input.add_argument("-i", "--iface", help="Interface to retrofit", type=str, required=True)
  input.add_argument("-l", "--lb", help="Linux bridge to retrofit", type=str, required=True)
  input.add_argument("-o", "--ovs", help="OVS bridge to retrofit", type=str, required=True)

  action = parser.add_argument_group("actions")
  action.add_argument("-f", "--force", help="Forcibly reconfigure interface", action="store_true")
  action.add_argument("action", help="Action to perform", choices=["bootstrap", "retrofit", "revert"], type=str)
  args = parser.parse_args()

  try:
    retro = Retrofit(args)
    if args.action == "bootstrap":
      retro.bootstrap()
    elif args.action == "retrofit":
      retro.retrofit()
    elif args.action == "revert":
      retro.revert()

  except Exception as e:
    print("Aborting due to exception:", e, file=sys.stderr)

if __name__ == "__main__":
  main()
