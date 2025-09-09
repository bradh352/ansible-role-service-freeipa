# Install and Configure FreeIPA Server

Author: Brad House<br/>
License: MIT<br/>
Original Repository: https://github.com/bradh352/ansible-role-service-freeipa

## Overview

FreeIPA is an open source identity and authorization provider that combines
Kerberos and LDAP to secure enterprise systems.

This role is used to set up a FreeIPA server.  It will also set up replicas
if part of a FreeIPA cluster.

This role must not be used with auth-freeipa or auth-sssd roles as the host
is automatically enrolled to the ipa domain.

This has only been tested on RedHat derivatives (specifically Rocky Linux 10).

## Variables used by this role

* `service_freeipa_admin_pass`: Password for the admin user.
* `service_freeipa_dm_pass`: Password for the Directory Manager.
* `service_freeipa_realm`: Realm name to set.  Typically the upper case version
  of the domain.

## Groups used by this role

* `freeipa_servers`: All servers must be a member of this group.  Servers will
  be joined together and replicate full-mesh.
