#!/usr/bin/env python

# Yay python 3.x
from __future__ import print_function, generators, division, nested_scopes, with_statement

import argparse
import ConfigParser
import os
import re
import shlex
import subprocess


def call(cmd, ignore=False):
  "Wrap subprocess.check_output"
  try:
    return subprocess.check_output(
      shlex.split(cmd),
      stderr=subprocess.STDOUT,
      universal_newlines=True
    )
  except subprocess.CalledProcessError as e:
    if not ignore:
      print("Error calling:", e.cmd)
      print("Exit code:", e.returncode)
      print("Output:", e.output)
      exit(e.returncode)
    else:
      return ""


class Config():
  "Retrofit config"
  def __init__(self, name=None, linuxBridge=None, ovsBridge=None):
    self.name = name
    self.linuxBridge = linuxBridge
    self.ovsBridge = ovsBridge

  # TODO: def parse(self, file="retrofit.conf"):


class Iface():
  "Parse interface and retrofit with OVS"
  def __init__(self, config):
    self.config = config
    self.name = config.name
    self.linuxBridge = config.linuxBridge
    self.ovsBridge = config.ovsBridge

  def prepare(self, iface):
    "Gather information"
    # TODO: Check if interface is in bridge already
    # raise Exception("{} is in bridge {}, pass -f to force")

    # Get interface config
    dump = call("ip -o addr show {}".format(iface))

    # Store MAC address
    self.mac = re.search("link/ether\s(\S+)", dump).group(1)

    # Store IP addresses
    self.ips = [
      ip
      for ip in re.findall("inet6?\s(\S+)", dump)
      if not ip.startswith("fe80") # Exclude link-local
    ]

    # Store routes
    self.routes = [
      " ".join(route.split())
      for route in call("ip -o route show dev {}".format(iface)).splitlines()
      if "kernel" not in route # Exclude automatic routes
    ]

  def retrofit(self, multi=False):
    "Retrofit interfaces"

    # Get current config
    self.prepare(self.ovsBridge)

    # Create linux bridge
    call("brctl addbr {}".format(self.linuxBridge), ignore=True)

    # Create veth pair
    call(
      "ip link add name phy-{0} type veth peer name ovs-{0}".format(
        self.linuxBridge),
      ignore=True
    )

    # Bring them up
    for dev in [self.name, self.linuxBridge, "phy-" + self.linuxBridge, "ovs-" + self.linuxBridge]:
      call("ip link set {} up".format(dev))

    # Stop keepalived before we change things
    call("service keepalived stop")

    # Modify configs to use the linux bridge
    for file in [
      file
      for file in os.listdir("/etc/keepalived/conf.d")
      if file.startswith("vrrp")
    ]:
      call(
        "sed -i 's/{}/{}/' {}".format(
          self.ovsBridge,
          self.linuxBridge,
          os.path.join("/etc/keepalived/conf.d", file)
        )
      )

    # Flush IPs from OVS bridge
    call("ip addr flush {}".format(self.ovsBridge))

    # Remove interface from OVS bridge
    call(
      "ovs-vsctl del-port {} {}".format(
        self.ovsBridge,
        self.name),
      ignore=True
    )

    # Add interfaces to linux bridge
    for dev in [self.name, "phy-" + self.linuxBridge]:
      call("brctl addif {} {}".format(self.linuxBridge, dev), ignore=True)

    # Set MAC address of linux bridge
    call("ip link set {} addr {}".format(self.linuxBridge, self.mac))

    # Add other veth interface to OVS bridge
    call(
      "ovs-vsctl add-port {} {}".format(
        self.ovsBridge,
        "ovs-" + self.linuxBridge
      ),
      ignore=True
    )

    # Add IPs to new linux bridge
    for ip in self.ips:
      call(
        "ip addr add dev {} {}".format(
          self.linuxBridge,
          ip
        ),
        ignore=True
      )

    # Add routes
    for route in self.routes:
      call("ip route add {}".format(route.replace(self.ovsBridge, self.linuxBridge)))

    # Start keepalived again
    call("service keepalived start")

  def revert(self):
    "Revert interfaces"

    # Get current config
    self.prepare(self.linuxBridge)

    # Stop keepalived before we change things
    call("service keepalived stop")

    # Modify configs to use the linux bridge
    for file in [
      file
      for file in os.listdir("/etc/keepalived/conf.d")
      if file.startswith("vrrp")
    ]:
      call(
        "sed -i 's/{}/{}/' {}".format(
          self.linuxBridge,
          self.ovsBridge,
          os.path.join("/etc/keepalived/conf.d", file)
        )
      )

    # Flush IPs from linux bridge
    call("ip addr flush {}".format(self.linuxBridge))

    # Remove interfaces from linux bridge
    for dev in [self.name, "phy-" + self.linuxBridge]:
      call("brctl delif {} {}".format(self.linuxBridge, dev), ignore=True)

    # Remove other veth interface from OVS bridge
    call(
      "ovs-vsctl del-port {} {}".format(
        self.ovsBridge,
        "ovs-" + self.linuxBridge
      ),
      ignore=True
    )

    # Delete veth pair
    call(
      "ip link delete phy-{0}".format(
        self.linuxBridge),
      ignore=True
    )

    # Set bridge down
    call("ip link set {} down".format(self.linuxBridge))

    # Delete linux bridge
    call("brctl delbr {}".format(self.linuxBridge), ignore=True)

    # Add interface to OVS bridge
    call(
      "ovs-vsctl add-port {} {}".format(
        self.ovsBridge,
        self.name),
      ignore=True
    )

    # Bring up OVS interface
    call("ip link set {} up".format(self.ovsBridge))

    # Add IPs to OVS interface
    for ip in self.ips:
      call(
        "ip addr add dev {} {}".format(
          self.ovsBridge,
          ip
        ),
        ignore=True
      )

    # Add routes
    for route in self.routes:
      call("ip route add {}".format(route.replace(self.linuxBridge, self.ovsBridge)))

    # Start keepalived again
    call("service keepalived start")


def main():
  parser = argparse.ArgumentParser()
  #parser.add_argument("-v", "--verbose", help="Verbose output of steps taken", action="store_true")
  #parser.add_argument("-q", "--quiet", help="Only output errors (to stderr)", action="store_true")
  #parser.add_argument("-c", "--config", help="Path to config file", type=str)
  parser.add_argument("-i", "--iface", help="Interface to retrofit", type=str, required=True)
  parser.add_argument("-l", "--lb", help="Linux bridge to retrofit", type=str, required=True)
  parser.add_argument("-o", "--ovs", help="OVS bridge to retrofit", type=str, required=True)
  args = parser.parse_args()

  try:
    config = Config(args.iface, args.lb, args.ovs)
    iface = Iface(config)
    iface.retrofit()
    #iface.revert()

    print("Iface:", iface.name)
    print("MAC:", iface.mac)
    print("IPs:", iface.ips)
    print("Routes:", iface.routes)

  except Exception as e:
    print("Error occurred:", e)

if __name__ == "__main__":
  main()
