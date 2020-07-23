# CA Unified Infrastructure Management Research

## Research

This repository will contain the majority of code written during my analysis of the Nimbus protocol. Unfortunately during the madness of everything I lost a few snippets. What originally spawned my curiosity to research this protocol was a recent pentest where we were able to get operating system information, installation directories, and more. All from an UNAUTHENTICATED perspective. Making this protocol BETTER than SNMP from an attacking perspective. In addition to this cloud providers have hundreds if not thousands of hosts running this protocol to monitor hosts.

## Vulnerabilities

| CVE | Description |
| ------------- | ------------- |
| CVE-2020-8010 | A remote attacker can execute commands, read from, or write to the target system. |
| CVE-2020-8011 | A remote attacker can crash the Controller service. |
| CVE-2020-8012 | A remote attacker can execute arbitrary code.  |

## Terminology

The following information was gathered from previous research done by [gdssecurity.](https://blog.gdssecurity.com/labs/2015/3/16/nimbus-protocol-enumeration-with-nmap.html)

- Domain: The Nimsoft domain is the logical descriptor that makes up many servers formed in a hierarchical structure. The domain is made up of Hubs and Robots.
- Robot: Every managed server that has Nimsoft installed on it will be known as a Robot. The Robot manages all Probes that can be configured.
- Hub: As part of a hierarchical architecture, a Hub is also a Robot but has the ability to manage child Robots in a tree-like structure.  A Hub manages a group of Robots and maintains central services.
- Probe: The specific program created that runs on a Robot. For example, there is a Hub probe that turns a Robot into a Hub.
- Primary Hub: This is the first choice Hub for a given Robot. A Robot can have many parent Hubs, and the Primary is where most messages get sent.
