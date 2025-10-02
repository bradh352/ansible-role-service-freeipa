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

A few things to note:
 - Will create a `service_accounts` group
 - Will create a `svc_admin` account that is in the admins and
   `service_accounts` groups, but will NOT be in the `ipa_users` group.  No
   password will be created but a keytab for this authentication will be stored
   on each FreeIPA server node.
 - Will create an enrollment user with the provided name and password.  This
   user will be added to `service_accounts`, but will NOT be in the `ipa_users`
   group.
 - For security reasons system logins shouldn't allow members to log into
   systems that are not part of the `ipa_users` group, for instance, service
   accounts as listed above.
 - A sudo rule is added called `sudo_allow_admins` which will allow anyone in
   the `admins` group to sudo on any host.

## Variables used by this role

* `service_freeipa_admin_pass`: Password for the admin user.
* `service_freeipa_dm_pass`: Password for the Directory Manager.
* `service_freeipa_domain`: Domain name to set.
* `service_freeipa_realm`: Realm name to set.  Typically the upper case version
  of the domain.
* `service_freeipa_bind_user`: Username to create for use with ldap bind
  operations.  Defaults to `bind` if not specified.  Generates a full bind user
  name like `uid={{ service_freeipa_bind_user }},cn=sysaccounts,cn=etc,dc={{ service_freeipa_domain | split(".") | join(",dc=") }}`
* `service_freeipa_bind_pass`: Password to assign for the created bind user.
* `service_freeipa_enroll_user`: Username for enrollment user.  Recommended to
  use something like `svc_enroll`.
* `service_freeipa_enroll_pass`: Password to assign to the enrollment user.
  Will be used to enroll any systems into the IPA Realm.

### Variables for syncing from a remote IDP
* `service_freeipa_idp_proxy`: If a proxy is necessary to connect to the IdP to
  receive the device code and perform validation then this should be a URI
  to the proxy, e.g. `https://proxy.testenv.bradhouse.dev:8080`.  This will
  be added to `/etc/ipa/default.conf`.
* `service_freeipa_idp_noproxy`: List of domains to NOT attempt to proxy. A
  leading `.` is used to act as a wildcard (rather than `*`).
  E.g. `[ "testenv.bradhouse.dev", ".testenv.bradhouse.dev" ]`
* `service_freeipa_idpsync_enable`: Boolean.  Whether or not to sync users from
  an idp's ldap server. The remaining `service_freeipa_idpsync_*` configuration
  values should be set when this is enabled.
* `service_freeipa_idpsync_idp_name`: Required. Name of IDP provider registered
  in FreeIPA to associate users with.
* `service_freeipa_idpsync_provider`: Required. One of the supported FreeIPA
  providers.  Only `okta` has been tested.
* `service_freeipa_idpsync_provider_url`: Required. Base URL for IDP provider
  OAuth2 endpoint.
* `service_freeipa_idpsync_clientid`: Required. Client ID for IDP OAuth2
  provider.
* `service_freeipa_idpsync_local_users`: List of local users to ignore for
  syncing purposes.  Defaults to `[ "admin" ]`.
* `service_freeipa_idpsync_local_groups`: List of local groups to ignore for
  syncing purposes.  Defaults to
  `[ "admins", "editors", "ipausers", "trust admins" ]`.
* `service_freeipa_idpsync_server`: Required. Server for LDAP syncing of
  users / groups.
* `service_freeipa_idpsync_use_ssl`: Boolean, whether or not SSL / TLS is
  required. Defaults to `true`.
* `service_freeipa_idpsync_binddn`: Required. Bind DN for requesting
  users/groups.
* `service_freeipa_idpsync_bindpass`: Required. Bind DN's password for
  requesting users/groups.
* `service_freeipa_idpsync_userdn`: Required. User DN base for LDAP.
* `service_freeipa_idpsync_groupdn`: Required. Group DN base for LDAP.
* `service_freeipa_idpsync_ignore_users`: List of users to NOT import from
  upstream IDP.
* `service_freeipa_idpsync_ignore_groups`: List of groups to ignore from
  upstream IDP.
* `service_freeipa_idpsync_attr_username`: LDAP attribute for username, defaults
  to `uid`.
* `service_freeipa_idpsync_attr_fullname`: LDAP attribute for full name,
  defaults to `cn`.
* `service_freeipa_idpsync_attr_fname`: LDAP attribute for first name, defaults
  to `givenName`.
* `service_freeipa_idpsync_attr_lname`: LDAP attribute for last name, defaults
  to `sn`.
* `service_freeipa_idpsync_attr_email`: LDAP attribute for email, defaults to
  `mail`.
* `service_freeipa_idpsync_attr_shell`: LDAP attribute for login shell, defaults
  to `loginShell`.
* `service_freeipa_idpsync_attr_uid`: LDAP attribute for POSIX uid, defaults
  to `uidNumber`.
* `service_freeipa_idpsync_attr_active`: LDAP attribute for determining if the
  user is active. Defaults to `organizationalStatus`.
* `service_freeipa_idpsync_active_values`: Values for
  `service_freeipa_idpsync_attr_active` that indicate the user is active.
  Defaults to `["ACTIVE","PASSWORD_EXPIRED"]`
* `service_freeipa_idpsync_attr_group_name`: LDAP attribute for group name,
  defaults to `cn`.
* `service_freeipa_idpsync_attr_group_desc`: LDAP attribute for group
  description, defaults to `description`.
* `service_freeipa_idpsync_attr_group_members`: LDAP attribute for group
  members, defaults to `uniqueMember`.


## Groups used by this role

* `freeipa_servers`: All servers must be a member of this group.  Servers will
  be joined together and replicate full-mesh.

## TODO

* Figure out security implications of /etc/krb5.admin.keytab which allows admin
  to authenticate without a password on the server.
* Figure out if we can enroll a host using the admin keytab without a password
  otherwise we should have a host enrollment user.
* Determine if `service_freeipa_admin_pass` and `service_freeipa_dm_pass` are
  only really required on initial bring-up of first node.
* See what happens to /etc/krb5.admin.keytab if the admin user's password changes.
   * If its invalidated, we should probably create a separate admin user with a
     random password for the /etc/krb5.admin.keytab purposes.
