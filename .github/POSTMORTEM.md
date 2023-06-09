---
# This is a template for a postmortem reports inspired by
#   the teamdigitale's one published on medium.com.
#   For the original version, see the references section.
title: Fake Postmortem - Cloud connectivity incident
date: 2018-05-23
summary: >-
  Fake Postmortem inspired by the following: The Digital Team's websites were unreachable for 28 hours due to a cloud provider
  outage.
authors:
- name: Mario Rossi
- name: Franco Bianchi
references:
- https://medium.com/team-per-la-trasformazione-digitale/document-postmortem-technology-italian-government-public-administration-99639a0a7877
- https://abseil.io/resources/swe-book/html/ch02.html#blameless_postmortem_culture
glossary: {}
keywords: []
...
---
# Postmortem - Template for a postmortem report

## Summary

**Impact**:

The following services cannot be reached:

- Dashboard Team
- Three-Year ICT Plan
- Designers Italia
- Developers Italia
- Docs Italia
- Forum Italia

**Duration**:
28 hours

**Cause**:
OpenStack network outage - cloud provider _Cloud SPC Lotto 1_

## Context

The Digital Team's websites are based mainly on static HTML generated by the source content of the repositories on GitHub. The HTML code is published via a web server (nginx) and exposed according to HTTPS protocol. Forum Italia (http://forum.italia.it) is the only exception to this deployment model, and is managed separately via Docker containers. At any given time, one or more web servers can be deployed on the cloud provider's (Cloud SPC Lotto 1) OpenStack virtual machines, using the API provided by the platform.

Cloud resources (virtual machines and volume data) are allocated towards services according to the Agency for Digital Italy's Cloud SPC contract.

## Impact and damage assessment

On 19/05/2018, the following services became unreachable due to an internal connectivity issue of the Cloud Service Provider "Cloud SPC":

- Dashboard Team
- Three-Year ICT Plan
- Designers Italia
- Developers Italia
- Docs Italia
- Forum Italia

## Causes and Contributing Factors

According to a postmortem document released by the supplier on 2018-06-07, the interruption of connectivity experienced by the 31 users (tenants) of the SPC Cloud service was triggered by a planned update of the OpenStack platform carried out on the night of Thursday 2018-05-17.

### Detection

The problem was detected the following morning (2018-05-18), thanks to reports from users who were no longer able to access the services provided on the Cloud SPC platform.

### Causes

The document states that a restart of the control nodes of the OpenStack platform (nodes that handle OpenStack's management services: neutron, glance, cinder, etc.) caused “an anomaly” in the network infrastructure, blocking the traffic on several computing nodes (nodes where virtual instances are executed), and causing virtual machines belonging to 31 users to become unreachable.
The postmortem document also explains how a bug in the playbook (update script) would have blocked network activities by modifying the permissions of the file `/var/run/neutron/lock/neutron-iptables`, as indicated in the platform's official documentation.

Again, according to the supplier, restarting the nodes was necessary for the application of security updates for Meltdown and Spectre (CVE-2017-5715, CVE-2017-5753 and CVE-2017-5754).

The unavailability of the Cloud SPC infrastructure was undoubtedly the root cause of the problem, but the lack of an application-level protection mechanism for the Digital Team's services prolonged their unavailability.
Indeed, due to the fact that the possibility of the entire cloud provider becoming unreachable had not been taken into account during the design phase of the services, it was not possible to respond adequately to this event.
Despite the SPC Cloud provider's failover mechanisms, the web services were not protected from generalized outages capable of undermining the entire infrastructure of the only Cloud provider at our disposal.

## Actions taken

WRITEME: A list of action items taken to mitigate/fix the problem

- * Action  1
  * Owner
- * Action 2
  * Owner
...

## Preventive actions

WRITEME: A list of action items to prevent this from happening again



## Lessons learned

### What went wrong

The Cloud SPC platform cannot currently distribute virtual machines through data centers or different regions (OpenStack region).
It would have been useful to be able to distribute virtual resources through independent infrastructures, even infrastructures provided by the same supplier.

### What should have been done

In hindsight, the Public Administration should have access to multiple cloud providers, so as to ensure the resilience of its services even when the main cloud provider is interrupted.

### Where we got lucky

WRITEME: What things went right that could have gone wrong

### What should we do differently next time

The most important lesson we learned from this experience is the need to continue investing in the development of a cross-platform, multi-supplier Cloud model.
This model would guarantee the reliability of Public Administration services even when the main cloud provider becomes affected by problems that make it unreachable for a long period of time.

## Timeline

A timeline of the event, from discovery through investigation to resolution.
All times are in CEST.

### 2018-05-17

22.30 CEST: The SPC MaaS alert service sends alerts through email indicating that several nodes can no longer be reached. <START of programmed activities>

### 2018-05-19

6:50 CEST: The aforementioned services, available at the IP address 91.206.129.249, can no longer be reached <START of INTERRUPTION>

### 2018-05-19

08:00 CEST: The problem is detected and reported to the supplier

09:30 CEST: The machines are determined to be accessible through OpenStack's administration interface (API and GUI) and internal connectivity reveals no issue. Virtual machines can communicate through the tenant's private network, but do not connect to the Internet.

15:56 CEST: The Digital Team sends the supplier and CONSIP a help request via email

18:00 CEST: The supplier communicates that they have identified the problem, which turns out to be the same problem experienced by the DAF project, and commence work on a manual workaround

19:00 CEST: The supplier informs us that a fix has been produced and that it will be applied to the virtual machines belonging to the 31 public administrations (tenants) involved.

### 2018-05-20

11:10 CEST: The supplier restores connectivity to the VMs of the AgID tenant

11:30 CEST: The Digital Team reboots the web services and the sites are again reachable <END OF INTERRUPTION>
