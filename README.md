Retrofit
========

# A little tool to retrofit single-OVS-bridge nodes for safer operation or multi-NIC upgrades

This tool is designed to assist with configuring or retrofitting an OpenStack cluster host with a "Combined Plane" network architecture,


Combined Plane
---

"Combined Plane" refers to the combination of Control Plane and Data Plane traffic, going over the same logical network.


Separated Plane
---

"Separated Plane" refers to the separation of Control Plane and Data Plane traffic, with each going over separate logical networks.
