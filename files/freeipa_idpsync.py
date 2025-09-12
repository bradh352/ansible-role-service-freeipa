#!/usr/bin/env python3
"""Script used to sync from an IDP as a source of truth to FreeIPA"""

import configparser
import urllib3
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import click
import ldap3
from python_freeipa import ClientMeta

urllib3.disable_warnings()


@dataclass
class User:
    """Data class containing all user attributes we care about"""

    username: str
    name: str
    fname: str
    lname: str
    shell: Optional[str]
    uid: Optional[str]
    active: bool
    email: Optional[str]
    auth_type: str
    idp_name: str
    idp_username: str


@dataclass
class Group:
    """Data class containing all group attributes we care about"""

    name: str
    description: Optional[str]
    members: Dict[str, None]


@click.command()
@click.option(
    "--config-path",
    type=click.Path(exists=True, readable=True),
    default="./freeipa_idpsync.conf",
    help="Configuration Path.",
)
@click.option(
    "--freeipa-password",
    prompt=True,
    hide_input=True,
    help="FreeIPA password",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Output what would be done",
)
def sync(config_path: str, freeipa_password: str, dry_run: bool):
    """Sync users and groups from IDP to FreeIPA"""
    config = configparser.ConfigParser()
    config.read(config_path)

    client = ClientMeta(config["freeipa"]["server"], verify_ssl=strtobool(config["freeipa"]["verify_ssl"]))
    client.login(config["freeipa"]["username"], freeipa_password)

    idp_users, idp_groups = fetch_ldap(config, idp_password)
    freeipa_users, freeipa_groups = fetch_freeipa(client, config)

    if dry_run:
        print("== DRY RUN ==")

    new_users = users_not_in(idp_users, freeipa_users)
    if len(new_users):
        print(f" * Adding {len(new_users)} new users")
        for user in new_users:
            freeipa_user_add(client, user, dry_run)

    deleted_users = users_not_in(freeipa_users, idp_users)
    if len(deleted_users):
        print(f" * Deleting {len(deleted_users)} users")
        for user in deleted_users:
            freeipa_user_del(client, user, dry_run)

    new_groups = groups_not_in(idp_groups, freeipa_groups)
    if len(new_groups):
        print(f" * Adding {len(new_groups)} new groups")
        for group in new_groups:
            freeipa_group_add(client, group, dry_run)

    deleted_groups = groups_not_in(freeipa_groups, idp_groups)
    if len(deleted_groups):
        print(f" * Deleting {len(deleted_groups)} groups")
        for group in deleted_groups:
            freeipa_group_del(client, group, dry_run)

    updated_users = modified_users(idp_users, freeipa_users)
    if len(updated_users):
        print(f"  * Updating {len(updated_users)} users")
        for user in updated_users:
            freeipa_user_mod(client, user, dry_run)

    updated_groups = modified_groups(idp_groups, freeipa_groups)
    if len(updated_groups):
        print(f"  * Updating {len(updated_groups)} groups")
        for group in updated_groups:
            freeipa_group_mod(client, group, freeipa_groups[group.name], idp_users, dry_run)

    print("Sync Complete")


def freeipa_user_add(client: ClientMeta, user: User, dry_run: bool):
    """
    Add a user into FreeIPA

    Parameters:
        client [ClientMeta]: Connected and logged in FreeIPA session
        user [User]: User attributes to add
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        python_freeipa.exceptions.BadRequest
    """

    print(f"   * Adding User {user.username}")
    if dry_run:
        return

    client.user_add(
        a_uid=user.username,
        o_givenname=user.fname,
        o_sn=user.lname,
        o_cn=user.name,
        o_gecos=user.name,
        o_mail=user.email,
        o_ipauserauthtype=user.auth_type,
        o_ipaidpconfiglink=user.idp_name,
        o_ipaidpsub=user.idp_username,
        o_uidnumber=user.uid,
        o_gidnumber=user.uid,
        o_loginshell=user.shell,
        o_nsaccountlock=False if user.active else True,
    )


def freeipa_user_mod(client: ClientMeta, user: User, dry_run: bool):
    """
    Modify existing FreeIPA user.  At least one data element must differ or an exception will be thrown.

    Parameters:
        client [ClientMeta]: Connected and logged in FreeIPA session
        user [User]: User attributes to modify
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        python_freeipa.exceptions.BadRequest
    """

    print(f"   * Updating User {user.username}")
    if dry_run:
        return

    client.user_mod(
        a_uid=user.username,
        o_givenname=user.fname,
        o_sn=user.lname,
        o_cn=user.name,
        o_gecos=user.name,
        o_mail=user.email,
        o_ipauserauthtype=user.auth_type,
        o_ipaidpconfiglink=user.idp_name,
        o_ipaidpsub=user.idp_username,
        o_uidnumber=user.uid,
        o_gidnumber=user.uid,
        o_loginshell=user.shell,
        o_nsaccountlock=False if user.active else True,
    )


def freeipa_user_del(client: ClientMeta, user: User, dry_run: bool):
    """
    Delete existing FreeIPA user.

    Parameters:
        client [ClientMeta]: Connected and logged in FreeIPA session
        user [User]: User to delete
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        python_freeipa.exceptions.BadRequest
    """

    print(f"   * Deleting User {user.username}")
    if dry_run:
        return

    client.user_del(
        a_uid=user.username,
        o_preserve=False,
    )


def freeipa_group_add(client: ClientMeta, group: Group, dry_run: bool):
    """
    Add FreeIPA group and members to group

    Parameters:
        client [ClientMeta]: Connected and logged in FreeIPA session
        group [Group]: Group to add with members
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        python_freeipa.exceptions.BadRequest
    """

    print(f"   * Adding Group {group.name}")

    if not dry_run:
        client.group_add(
            a_cn=group.name,
            o_description=group.description,
        )

    if len(group.members):
        print(f"     * Adding {len(group.members)} members")
        for member in group.members:
            print(f"       * Adding member {member}")
            if not dry_run:
                client.group_add_member(
                    a_cn=group.name,
                    o_user=member,
                )


def freeipa_group_mod(
    client: ClientMeta, idpgroup: Group, freeipagroup: Group, idp_users: Dict[str, User], dry_run: bool
):
    """
    Add FreeIPA group to modify.  Will also update group membership

    Parameters:
        client [ClientMeta]: Connected and logged in FreeIPA session
        idpgroup [Group]: Updated group from IDP
        freeipagroup [Group]: Current group data from FreeIPA.  Used to compare changes such as group membership.
        idp_users [Dict[str, User]]: List of known users to the IDP.  Used to exclude group membership changes for
            deleted users.
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        python_freeipa.exceptions.BadRequest
    """

    print(f"   * Updating Group {idpgroup.name}")

    if not dry_run:
        # Only thing that can change is the description, we will get an error if we try to modify with no changes.
        if idpgroup.description != freeipagroup.description:
            client.group_mod(
                a_cn=idpgroup.name,
                o_description=idpgroup.description,
            )

    if idpgroup.members != freeipagroup.members:
        for member in idpgroup.members:
            if member not in freeipagroup.members:
                print(f"     * Adding member {member}")
                if not dry_run:
                    client.group_add_member(a_cn=idpgroup.name, o_user=member)
        for member in freeipagroup.members:
            if member not in idpgroup.members:
                # On user deletion, we've pre-cached group membership, but it will be auto-removed so skip
                # deleted users.
                if member not in idp_users:
                    continue
                print(f"     * Removing member {member}")
                if not dry_run:
                    client.group_remove_member(a_cn=idpgroup.name, o_user=member)


def freeipa_group_del(client: ClientMeta, group: Group, dry_run: bool):
    """
    Add FreeIPA group to delete.

    Parameters:
        client [ClientMeta]: Connected and logged in FreeIPA session
        group [Group]: Group to delete
        dry_run [bool]: If true, only print what would occur.

    Exceptions:
        python_freeipa.exceptions.BadRequest
    """

    print(f"   * Deleting Group {group.name}")
    if not dry_run:
        client.group_del(a_cn=group.name)


def fetch_string(values: Dict, name: Optional[str]) -> Optional[str]:
    """
    Fetch a string value from a dictionary.  If the value located is a list,
    will return the first entry in the list.  If the value located is a byte
    array, will convert it to utf-8.

    Parameters:
        values [Dict]: Dictionary to query for string
        name [str]: Name to search in dictionary

    Returns:
        String value if found otherwise None
    """

    if name is None or len(name) == 0:
        return None

    val = values.get(name)
    if not val:
        return None

    if isinstance(val, list):
        val = val[0]

    if isinstance(val, bytes):
        val = val.decode("utf-8")

    if not isinstance(val, str):
        val = str(val)

    return val


def fetch_required_string(values: dict, name: str) -> str:
    """
    Fetch a string value from a dictionary.  If the value located is a list,
    will return the first entry in the list.  If the value located is a byte
    array, will convert it to utf-8.

    Parameters:
        values [Dict]: Dictionary to query for string
        name [str]: Name to search in dictionary

    Returns:
        String value

    Exceptions:
        Exception if name is invalid or value not found.
    """

    if len(name) == 0:
        raise Exception("name must have length greater than 0")

    val = fetch_string(values, name)
    if val is None:
        raise Exception(f"{name} does not exist")

    return val


def strtobool(val: str) -> bool:
    """
    Convert provided string value into a boolean.

    Supports y, yes, t, true, on, 1 as truth values, all other values are False.

    Parameters:
        val [str]: value to interpret

    Returns:
        bool
    """

    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return True
    return False


def fetch_ldap(config: configparser.ConfigParser, password: str) -> Tuple[Dict[str, User], Dict[str, Group]]:
    """
    Retrieve all users an groups from LDAP server

    Parameters:
        config [ConfigParser]: Configuration containing "idp:ldap" section with appropriate parameters
        password [str]: Password for "binddn" user

    Returns:
        Users [Dict[str, User]]: Dictionary of users.  The key is the username, the value is a class User instance.
        Groups [Dict[str, Group]]: Dictionary of groups. The key is the group name, the value is a class Group instance.

    Exceptions:
        LDAPException
        Exception
    """

    server = ldap3.Server(config["idp:ldap"]["server"], use_ssl=strtobool(config["idp:ldap"]["use_ssl"]))
    conn = ldap3.Connection(server, config["idp:ldap"]["binddn"], config["idp:ldap"]["bindpass"], auto_bind=True)
    conn.search(
        search_base=config["idp:ldap"]["userdn"],
        search_filter="(objectclass=*)",
        attributes=ldap3.ALL_ATTRIBUTES,
    )

    ignore_users = config["idp:ldap"]["ignore_users"].split(",")
    ignore_groups = config["idp:ldap"]["ignore_groups"].split(",")
    active_values = config["idp:ldap"]["attr_active_values"].split(",")

    if conn.response is None:
        raise Exception("user search failed")

    users = {}
    for row in conn.response:
        attr = row["raw_attributes"]

        idp_username = fetch_string(attr, config["idp:ldap"]["attr_username"])
        if idp_username is None or idp_username in ignore_users:
            continue

        # Usernames in the form of an email address must remove the suffix.
        username = idp_username.split("@")[0]

        user = User(
            username=username,
            fname=fetch_required_string(attr, config["idp:ldap"]["attr_fname"]),
            lname=fetch_required_string(attr, config["idp:ldap"]["attr_lname"]),
            name=fetch_required_string(attr, config["idp:ldap"]["attr_name"]),
            email=fetch_string(attr, config["idp:ldap"].get("attr_email")),
            uid=fetch_string(attr, config["idp:ldap"].get("attr_uid")),
            auth_type="idp",
            idp_name=config["freeipa"]["idp_name"],
            idp_username=idp_username,
            shell=fetch_string(attr, config["idp:ldap"].get("attr_shell")),
            active=True if fetch_required_string(attr, config["idp:ldap"]["attr_active"]) in active_values else False,
        )

        if user.username in users:
            raise Exception(f"Duplicate user {user.username}")

        users[user.username] = user

    conn.search(
        search_base=config["idp:ldap"]["groupdn"],
        search_filter="(objectclass=*)",
        attributes=ldap3.ALL_ATTRIBUTES,
    )

    if conn.response is None:
        raise Exception("group search failed")

    groups = {}
    for row in conn.response:
        attr = row["raw_attributes"]

        if not attr.get("uniqueIdentifier"):
            continue

        members = {}
        if attr.get(config["idp:ldap"]["attr_group_members"]):
            for member in attr.get(config["idp:ldap"]["attr_group_members"]):
                member = member.decode("utf-8")
                member = member.split(",")[0]
                member = member.split("=")[1]
                if member in ignore_users:
                    continue

                # If in email address form, split off just the username portion
                member = member.split("@")[0]

                # Stale reference?  Lets kill it.
                if not member in users:
                    continue

                members[member] = None

        group = Group(
            name=fetch_required_string(attr, config["idp:ldap"]["attr_group_name"]),
            description=fetch_string(attr, config["idp:ldap"].get("attr_group_description")),
            members=members,
        )

        if group.name is None or group.name in ignore_groups:
            continue

        groups[group.name] = group
    return users, groups


def fetch_freeipa(client: ClientMeta, config: configparser.ConfigParser) -> Tuple[Dict[str, User], Dict[str, Group]]:
    """
    Fetch users and groups from FreeIPA

    Parameters:
      client [python_freeipa.ClientMeta]: Connected and Authenticated FreeIPA session
      config [ConfigParser]: Configuration object containing a "freeipa" section

    Returns:
        Users [Dict[str, User]]: Dictionary of users.  The key is the username, the value is a class User instance.
        Groups [Dict[str, Group]]: Dictionary of groups. The key is the group name, the value is a class Group instance.

    Exceptions:
        python_freeipa.exceptions.BadRequest
    """

    ignore_users = config["freeipa"]["ignore_users"].split(",")
    ignore_groups = config["freeipa"]["ignore_groups"].split(",")

    result = client.user_find()
    users = {}
    for row in result["result"]:
        # the givenname may not exist for some users.  Blank is ok.
        fname = fetch_string(row, "givenname")
        if fname is None:
            fname = ""

        # If a user isn't an IDP user, these won't be set.  Use blank.
        auth_type = fetch_string(row, "ipauserauthtype")
        if auth_type is None:
            auth_type = "password"
        idp_name = fetch_string(row, "ipaidpconfiglink")
        if idp_name is None:
            idp_name = ""
        idp_username = fetch_string(row, "ipaidpsub")
        if idp_username is None:
            idp_username = ""

        user = User(
            username=fetch_required_string(row, "uid"),
            fname=fname,
            lname=fetch_required_string(row, "sn"),
            name=fetch_required_string(row, "cn"),
            email=fetch_string(row, "mail"),
            uid=fetch_required_string(row, "uidnumber"),
            auth_type=auth_type,
            idp_name=idp_name,
            idp_username=idp_username,
            shell=fetch_string(row, "loginshell"),
            active=False if row["nsaccountlock"] else True,
        )

        if user.username in ignore_users:
            continue

        users[user.username] = user

    result = client.group_find()
    groups = {}
    for row in result["result"]:
        members = {}
        member_user = row.get("member_user")
        if member_user is not None:
            for user in member_user:
                if not user in ignore_users:
                    members[user] = None

        group = Group(
            name=fetch_required_string(row, "cn"),
            description=fetch_string(row, "description"),
            members=members,
        )

        if group.name is None or group.name in ignore_groups:
            continue

        groups[group.name] = group

    return users, groups


def users_not_in(list1: Dict[str, User], list2: Dict[str, User]) -> List[User]:
    """
    Output list of users in list1 that are not in list2

    Parameters:
       list1 [Dict[str, User]]: List of desired users
       list2 [Dict[str, User]]: List of possible users

    Returns:
        users List[User]: list of users in list1 that are not in list2
    """

    return [user for user in list1.values() if user.username not in list2]


def groups_not_in(list1: Dict[str, Group], list2: Dict[str, Group]) -> List[Group]:
    """
    Output list of groups in list1 that are not in list2

    Parameters:
       list1 [Dict[str, Group]]: List of desired groups
       list2 [Dict[str, Group]]: List of possible groups

    Returns:
        users List[Group]: list of groups in list1 that are not in list2
    """
    return [group for group in list1.values() if group.name not in list2]


def user_match(idp_user: User, freeipa_user: User) -> bool:
    """
    Determine if the 2 users are identical.  If email, uid, or shell are not
    available in the IDP, will not check for match on those attributes.

    Parameters:
        idp_user [User]: IDP user
        freeipa_user [User]: FreeIPA user

    Returns:
        match [bool]: Whether or not user data matches
    """

    if idp_user.fname != freeipa_user.fname:
        return False
    if idp_user.lname != freeipa_user.lname:
        return False
    if idp_user.name != freeipa_user.name:
        return False
    if idp_user.email is not None and idp_user.email != freeipa_user.email:
        return False
    if idp_user.active != freeipa_user.active:
        return False
    if idp_user.auth_type != freeipa_user.auth_type:
        return False
    if idp_user.idp_name != freeipa_user.idp_name:
        return False
    if idp_user.idp_username != freeipa_user.idp_username:
        return False
    if idp_user.uid is not None and idp_user.uid != freeipa_user.uid:
        return False
    if idp_user.shell is not None and idp_user.shell != freeipa_user.shell:
        return False
    return True


def modified_users(idp_users: Dict[str, User], freeipa_users: Dict[str, User]) -> List[User]:
    """
    Determine the list of modified users.

    Parameters:
        idp_users [Dict[str, User]]: User list from IDP
        freeipa_users [Dict[str, User]]: User list from FreeIPA

    Returns:
        users [List[Users]]: List of modified users.  Excludes Added and Deleted users.
    """

    users = []
    for idp_user in idp_users.values():
        freeipa_user = freeipa_users.get(idp_user.username)
        if freeipa_user is None:
            continue
        if user_match(idp_user, freeipa_user):
            continue
        users.append(idp_user)
    return users


def group_match(idp_group: Group, freeipa_group: Group) -> bool:
    """
    Determine if the 2 groups are identical.

    Parameters:
        idp_group [Group]: IDP group
        freeipa_group [Group]: FreeIPA group

    Returns:
        match [bool]: Whether or not group data matches
    """

    if idp_group.description != freeipa_group.description:
        return False
    if idp_group.members != freeipa_group.members:
        return False
    return True


def modified_groups(idp_groups: Dict[str, Group], freeipa_groups: Dict[str, Group]) -> List[Group]:
    """
    Determine the list of modified groups.

    Parameters:
        idp_groups [Dict[str, Group]]: Group list from IDP
        freeipa_groups [Dict[str, Group]]: Group list from FreeIPA

    Returns:
        users [List[Groups]]: List of modified groups.  Excludes Added and Deleted groups.
    """
    groups = []
    for idp_group in idp_groups.values():
        freeipa_group = freeipa_groups.get(idp_group.name)
        if freeipa_group is None:
            continue
        if group_match(idp_group, freeipa_group):
            continue
        groups.append(idp_group)
    return groups


if __name__ == "__main__":
    sync()
