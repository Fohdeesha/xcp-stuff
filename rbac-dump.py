#!/usr/bin/env python3
"""rbac-dump - show Xen Orchestra's RBAC configuration as one readable report.

RBAC is the access control of the REST API and the XO 6 UI (the XO 5 JSON-RPC API still
uses the old ACLs, which this does not read). Its pieces are spread over four collections
that only point at each other by id:

    /acl-roles        name, privilegeIds, userIds, groupIds  (or isTemplate: built-ins)
    /acl-privileges   resource, action, selector, effect, roleId
    /users            permission (admin bypasses RBAC), groups
    /groups           users, aclRoleIds

This joins them: every role with its privileges and who holds it, then every user with
what they end up with - their own roles plus their groups' roles - and anything that does
not add up (dangling ids, roles nobody holds, users with no access at all).

USAGE
    rbac-dump.py https://xoa.example                  token from $XO_TOKEN
    rbac-dump.py https://xoa.example --user admin     password prompted (or $XO_PASSWORD)
    rbac-dump.py URL --json -o rbac.json              machine-readable
    rbac-dump.py URL --templates                      also list the built-in roles' privileges
    rbac-dump.py URL --server-effective               ask XO for each user's privileges too
    rbac-dump.py URL --for-user alice                 one user: their roles, groups, privileges
    rbac-dump.py URL --for-role "QA operators"        one role: its privileges and who holds it
    rbac-dump.py URL -k                               accept a self-signed certificate

WHAT IT NEEDS
    python3 >= 3.6 and nothing else. An admin login sees everything; any other login only
    sees what its own acl-role / acl-privilege / user / group read privileges allow, so
    the report is incomplete and says so. Read-only: only GET requests are sent.

RULES (https://docs.xen-orchestra.com/users-and-access/rbac)
    deny by default, deny beats allow, admins bypass everything, a parent action covers
    its children (`shutdown` covers `shutdown:clean`), `*` covers every action, and a
    privilege without a selector covers every object of its resource.
"""

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

NAME = "rbac-dump"
VERSION = "0.2"

API = "/rest/v0"
USER_FIELDS = "id,email,username,name,firstname,lastname,permission,groups,authProviders"
GROUP_FIELDS = "id,name,provider,users,aclRoleIds"


class ApiError(Exception):
    pass


class Client:
    def __init__(self, base, token=None, user=None, password=None, insecure=False):
        self.base = base.rstrip("/") + API
        self.headers = {"Accept": "application/json", "User-Agent": "%s/%s" % (NAME, VERSION)}
        if token:
            self.headers["Cookie"] = "authenticationToken=" + token
        elif user is not None:
            cred = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
            self.headers["Authorization"] = "Basic " + cred
        self.ctx = ssl._create_unverified_context() if insecure else None

    def get(self, path):
        req = Request(self.base + path, headers=self.headers)
        try:
            with urlopen(req, context=self.ctx, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            body = e.read().decode("utf-8", "replace").strip()
            if e.code == 401:
                raise ApiError("401 on %s: not logged in (bad token or password)" % path)
            raise ApiError("%d on %s: %s" % (e.code, path, body[:300]))
        except URLError as e:
            raise ApiError("cannot reach %s: %s" % (self.base, e.reason))

    def collection(self, path, fields="*"):
        return self.get("%s?fields=%s" % (path, quote(fields, safe=",*")))


# --------------------------------------------------------------------------------------
# fetch and join
# --------------------------------------------------------------------------------------

def fetch(client):
    return {
        "roles": client.collection("/acl-roles"),
        "privileges": client.collection("/acl-privileges"),
        "users": client.collection("/users", USER_FIELDS),
        "groups": client.collection("/groups", GROUP_FIELDS),
    }


def fetch_effective(client, uids):
    """XO's own answer to "what may this user do", per user id. One request each, so it is
    asked only for the users the report shows. A refusal is kept as the answer."""
    out = {}
    for uid in uids:
        try:
            out[uid] = client.collection("/users/%s/acl-privileges" % quote(uid))
        except ApiError as e:
            out[uid] = {"error": str(e)}
    return out


def _clean(obj):
    return {k: v for k, v in obj.items() if k != "href"}


def user_label(u):
    if u is None:
        return "?"
    return u.get("username") or u.get("email") or u.get("name") or u["id"]


def find_user(users, query):
    """The one user `query` names: an exact id, else a case-insensitive username, email or
    name. Anything else - no match, or several - is an ApiError naming the candidates."""
    for u in users:
        if u["id"] == query:
            return u
    q = query.lower()
    hits = [u for u in users
            if q in {(u.get(k) or "").lower() for k in ("username", "email", "name")}]
    if len(hits) == 1:
        return hits[0]
    if hits:
        raise ApiError("%r matches %d users: %s" % (
            query, len(hits), ", ".join("%s [%s]" % (user_label(u), u["id"]) for u in hits)))
    raise ApiError("no user %r among the %d this login can see: %s" % (
        query, len(users), ", ".join(sorted(user_label(u) for u in users)) or "-"))


def find_role(roles, query):
    """The one role `query` names: an exact id, else a case-insensitive name. Template
    roles count too. Anything else is an ApiError naming the candidates."""
    for r in roles:
        if r["id"] == query:
            return r
    hits = [r for r in roles if (r.get("name") or "").lower() == query.lower()]
    if len(hits) == 1:
        return hits[0]
    if hits:
        raise ApiError("%r matches %d roles: %s" % (
            query, len(hits), ", ".join("%s [%s]" % (r.get("name"), r["id"]) for r in hits)))
    raise ApiError("no role %r among the %d this login can see: %s" % (
        query, len(roles), ", ".join(sorted(r.get("name") or r["id"] for r in roles)) or "-"))


def focus_role(model, rid):
    """Cut the model down to one role: the role, the groups that hold it, every user who
    holds it directly or through one of those groups, and the warnings naming any of them."""
    role = next(r for r in model["roles"] + model["templates"] if r["id"] == rid)
    template = role in model["templates"]
    users = [u for u in model["users"] if any(r["id"] == rid for r in u["roles"])]
    groups = [g for g in model["groups"] if any(r["id"] == rid for r in g["roles"])]
    subjects = [repr(role["name"])] + [repr(x["name"]) for x in users + groups]
    return {
        "role": role,
        "roles": [] if template else [role],
        "templates": [role] if template else [],
        "users": users,
        "groups": groups,
        "warnings": [w for w in model["warnings"] if any(s in w for s in subjects)],
    }


def focus_user(model, uid):
    """Cut the model down to one user: the roles they hold, the groups they are in, and
    the warnings that name the user, one of those roles or one of those groups."""
    user = next(u for u in model["users"] if u["id"] == uid)
    role_ids = {r["id"] for r in user["roles"]}
    group_ids = {g["id"] for g in user["groups"]}
    roles = [r for r in model["roles"] if r["id"] in role_ids]
    groups = [g for g in model["groups"] if g["id"] in group_ids]
    subjects = [repr(user["name"])] + [repr(x["name"]) for x in roles + groups]
    return {
        "user": user,
        "roles": roles,
        "templates": [],
        "users": [user],
        "groups": groups,
        "warnings": [w for w in model["warnings"] if any(s in w for s in subjects)],
    }


def build(data):
    """Join the four collections into the report model. Pure: no I/O."""
    privs = {p["id"]: _clean(p) for p in data["privileges"]}
    users = {u["id"]: _clean(u) for u in data["users"]}
    groups = {g["id"]: _clean(g) for g in data["groups"]}
    roles = {r["id"]: _clean(r) for r in data["roles"]}
    warnings = []

    # A role's privileges: its privilegeIds, plus any privilege that names it as roleId.
    by_role = {rid: [] for rid in roles}
    seen = set()
    for rid, r in roles.items():
        for pid in r.get("privilegeIds", []):
            if pid in privs:
                by_role[rid].append(privs[pid])
                seen.add(pid)
            else:
                warnings.append("role %r lists privilege %s, which does not exist" % (r.get("name"), pid))
    for pid, p in privs.items():
        if pid in seen:
            continue
        if p.get("roleId") in roles:
            by_role[p["roleId"]].append(p)
            warnings.append("privilege %s names role %r but the role does not list it"
                            % (pid, roles[p["roleId"]].get("name")))
        else:
            warnings.append("privilege %s (%s %s on %s) belongs to missing role %s"
                            % (pid, p.get("effect"), p.get("action"), p.get("resource"), p.get("roleId")))

    for rid, r in roles.items():
        for p, other, why in pointless(by_role[rid]):
            warnings.append("role %r: privilege %s (%s) %s %s (%s)"
                            % (r.get("name"), p["id"], describe(p), why, other["id"], describe(other)))

    # Who holds each role, from both directions (role.userIds/groupIds and group.aclRoleIds).
    role_users = {rid: set(r.get("userIds", [])) for rid, r in roles.items()}
    role_groups = {rid: set(r.get("groupIds", [])) for rid, r in roles.items()}
    for gid, g in groups.items():
        for rid in g.get("aclRoleIds", []):
            if rid in roles:
                role_groups[rid].add(gid)
            else:
                warnings.append("group %r holds role %s, which does not exist" % (g.get("name"), rid))

    # Group membership, also from both directions.
    user_groups = {uid: set(u.get("groups", [])) for uid, u in users.items()}
    for gid, g in groups.items():
        for uid in g.get("users", []):
            user_groups.setdefault(uid, set()).add(gid)

    out_roles, out_templates = [], []
    for rid, r in sorted(roles.items(), key=lambda kv: (kv[1].get("name") or "").lower()):
        entry = {
            "id": rid,
            "name": r.get("name"),
            "description": r.get("description"),
            "privileges": sorted(by_role[rid], key=priv_key),
        }
        if r.get("isTemplate"):
            entry["roleTemplateId"] = r.get("roleTemplateId")
            out_templates.append(entry)
            if role_users[rid] or role_groups[rid]:
                warnings.append("template role %r is assigned directly (templates should be copied)"
                                % r.get("name"))
            continue
        for uid in sorted(role_users[rid]):
            if uid not in users:
                warnings.append("role %r is assigned to missing user %s" % (r.get("name"), uid))
        for gid in sorted(role_groups[rid]):
            if gid not in groups:
                warnings.append("role %r is assigned to missing group %s" % (r.get("name"), gid))
        entry["users"] = [{"id": uid, "name": user_label(users.get(uid))} for uid in sorted(role_users[rid])]
        entry["groups"] = [{"id": gid, "name": (groups.get(gid) or {}).get("name", "?")}
                           for gid in sorted(role_groups[rid])]
        if not entry["users"] and not entry["groups"]:
            warnings.append("role %r is not assigned to anyone" % r.get("name"))
        if not entry["privileges"]:
            warnings.append("role %r has no privileges" % r.get("name"))
        out_roles.append(entry)

    out_users = []
    for uid, u in sorted(users.items(), key=lambda kv: user_label(kv[1]).lower()):
        sources = []      # (role id, via) - via is None for a direct assignment, else group id
        for rid in roles:
            if uid in role_users[rid]:
                sources.append((rid, None))
            for gid in sorted(role_groups[rid] & user_groups.get(uid, set())):
                sources.append((rid, gid))
        effective = {}
        for rid, via in sources:
            for p in by_role[rid]:
                e = effective.setdefault(p["id"], dict(p, grantedBy=[]))
                e["grantedBy"].append({"role": roles[rid].get("name"),
                                       "via": None if via is None else (groups.get(via) or {}).get("name", via)})
        admin = u.get("permission") == "admin"
        entry = {
            "id": uid,
            "name": user_label(u),
            "email": u.get("email"),
            "admin": admin,
            "authProviders": sorted((u.get("authProviders") or {}).keys()),
            "groups": [{"id": gid, "name": (groups.get(gid) or {}).get("name", "?")}
                       for gid in sorted(user_groups.get(uid, set()))],
            "roles": [{"id": rid, "name": roles[rid].get("name"),
                       "via": None if via is None else (groups.get(via) or {}).get("name", via)}
                      for rid, via in sources],
            "effective": sorted(effective.values(), key=priv_key),
        }
        if not admin and not entry["effective"]:
            warnings.append("user %r is not an admin and has no RBAC privileges (no REST/XO 6 access)"
                            % entry["name"])
        out_users.append(entry)

    out_groups = []
    for gid, g in sorted(groups.items(), key=lambda kv: (kv[1].get("name") or "").lower()):
        out_groups.append({
            "id": gid,
            "name": g.get("name"),
            "provider": g.get("provider"),
            "users": [{"id": uid, "name": user_label(users.get(uid))} for uid in sorted(g.get("users", []))],
            "roles": [{"id": rid, "name": roles[rid].get("name")}
                      for rid in sorted(roles) if gid in role_groups[rid]],
        })

    return {"roles": out_roles, "templates": out_templates, "users": out_users,
            "groups": out_groups, "warnings": warnings}


def covers(broad, narrow):
    """True when `broad` applies to every (action, object) `narrow` does: same resource, an
    action that is `*`, the same, or a parent (`shutdown` over `shutdown:clean`), and no
    selector or the same one. Two different selectors are never compared - whether they
    overlap depends on the objects, so that is left alone rather than guessed."""
    if broad.get("resource") != narrow.get("resource"):
        return False
    ba, na = broad.get("action") or "", narrow.get("action") or ""
    if not (ba == "*" or ba == na or na.startswith(ba + ":")):
        return False
    bs, ns = (broad.get("selector") or "").strip(), (narrow.get("selector") or "").strip()
    return not bs or bs == ns


def pointless(privs):
    """The privileges of one role that change nothing, as (privilege, other, reason):
    an exact duplicate, one a broader privilege of the same effect covers, or an allow a
    deny cancels (deny wins). Of two identical privileges the later id is reported."""
    out = []
    privs = sorted(privs, key=lambda p: p["id"])
    for i, p in enumerate(privs):
        for j, other in enumerate(privs):
            if i == j or not covers(other, p):
                continue
            if other.get("effect") == p.get("effect"):
                if covers(p, other):          # identical in effect: report only the later one
                    if j < i:
                        out.append((p, other, "duplicates"))
                        break
                else:
                    out.append((p, other, "is already covered by"))
                    break
            elif p.get("effect") == "allow":
                out.append((p, other, "is cancelled by the deny"))
                break
    return out


def describe(p):
    return "%s %s %s%s" % (p.get("effect"), p.get("action"), p.get("resource"),
                           " where " + p["selector"] if p.get("selector") else "")


def priv_key(p):
    return (p.get("resource") or "", p.get("effect") != "deny", p.get("action") or "", p.get("selector") or "")


# --------------------------------------------------------------------------------------
# text report
# --------------------------------------------------------------------------------------

def fmt_priv(p):
    sel = p.get("selector")
    return "%-5s %-18s %-24s %s" % (p.get("effect"), p.get("resource"), p.get("action"),
                                    sel if sel else "(all objects)")


def names(items):
    return ", ".join(i["name"] for i in items) if items else "-"


def render(model, source, show_templates):
    if "user" in model:
        lines = ["RBAC of user %s [%s] on %s  (%s %s)" % (model["user"]["name"], model["user"]["id"], source,
                                                         NAME, VERSION)]
        lines += render_users(model)
        lines += render_roles(model)
        lines += render_groups(model)
    elif "role" in model:
        lines = ["RBAC of role %s [%s] on %s  (%s %s)" % (model["role"]["name"], model["role"]["id"], source,
                                                         NAME, VERSION)]
        lines += render_roles(model) if model["roles"] else render_templates(model, True)
        lines += render_groups(model)
        lines += render_users(model)
    else:
        lines = ["RBAC configuration of %s  (%s %s)" % (source, NAME, VERSION)]
        lines += render_roles(model)
        lines += render_templates(model, show_templates)
        lines += render_groups(model)
        lines += render_users(model)
    lines.append("")
    lines.append("WARNINGS (%d)" % len(model["warnings"]))
    for w in model["warnings"]:
        lines.append("  - " + w)
    return "\n".join(lines) + "\n"


def render_roles(model):
    lines = ["", "ROLES (%d)" % len(model["roles"])]
    for r in model["roles"]:
        lines.append("")
        lines.append("  %s  [%s]" % (r["name"], r["id"]))
        if r.get("description"):
            lines.append("    %s" % r["description"])
        lines.append("    users:  %s" % names(r["users"]))
        lines.append("    groups: %s" % names(r["groups"]))
        for p in r["privileges"]:
            lines.append("      " + fmt_priv(p))
        if not r["privileges"]:
            lines.append("      (no privileges)")
    return lines


def render_templates(model, show_templates):
    lines = [""]
    lines.append("TEMPLATE ROLES (%d, built-in, copy before use)" % len(model["templates"]))
    for t in model["templates"]:
        lines.append("  %s  [%s]  %d privileges" % (t["name"], t["id"], len(t["privileges"])))
        if show_templates:
            for p in t["privileges"]:
                lines.append("      " + fmt_priv(p))
    return lines


def render_groups(model):
    lines = [""]
    lines.append("GROUPS (%d)" % len(model["groups"]))
    for g in model["groups"]:
        prov = " (%s)" % g["provider"] if g.get("provider") else ""
        lines.append("  %s%s  [%s]" % (g["name"], prov, g["id"]))
        lines.append("    members: %s" % names(g["users"]))
        lines.append("    roles:   %s" % names(g["roles"]))
    return lines


def render_users(model):
    lines = [""]
    lines.append("USERS (%d)" % len(model["users"]))
    for u in model["users"]:
        lines.append("")
        tag = "  ADMIN - bypasses RBAC" if u["admin"] else ""
        lines.append("  %s  [%s]%s" % (u["name"], u["id"], tag))
        if u["authProviders"]:
            lines.append("    auth:   %s" % ", ".join(u["authProviders"]))
        lines.append("    groups: %s" % names(u["groups"]))
        roles = ["%s (via %s)" % (r["name"], r["via"]) if r["via"] else r["name"] for r in u["roles"]]
        lines.append("    roles:  %s" % (", ".join(roles) if roles else "-"))
        if u["effective"]:
            lines.append("    effective privileges:")
            for p in u["effective"]:
                lines.append("      " + fmt_priv(p))
        elif not u["admin"]:
            lines.append("    effective privileges: none (denied everything)")
        se = u.get("serverEffective")
        if isinstance(se, dict) and "error" in se:
            lines.append("    server says: %s" % se["error"])
        elif se is not None:
            mine = {p["id"] for p in u["effective"]}
            theirs = {p["id"] for p in se}
            if mine == theirs:
                lines.append("    server agrees: %d privileges" % len(theirs))
            else:
                lines.append("    server differs: only here %s, only on server %s"
                             % (sorted(mine - theirs) or "-", sorted(theirs - mine) or "-"))
    return lines


# --------------------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Dump Xen Orchestra RBAC roles, privileges and assignments.")
    ap.add_argument("--version", action="version", version="%s %s" % (NAME, VERSION))
    ap.add_argument("url", help="XO base URL, e.g. https://xoa.example (without /rest/v0)")
    ap.add_argument("--token", help="authentication token (default: $XO_TOKEN)")
    ap.add_argument("--user", help="log in with HTTP basic auth as this user instead of a token")
    ap.add_argument("-k", "--insecure", action="store_true", help="do not verify the TLS certificate")
    ap.add_argument("--json", action="store_true", help="write JSON instead of the text report")
    ap.add_argument("--raw", action="store_true", help="with --json: the four collections as fetched, unjoined")
    ap.add_argument("--templates", action="store_true", help="list the template roles' privileges too")
    ap.add_argument("--server-effective", action="store_true",
                    help="also fetch /users/<id>/acl-privileges and compare with the computed set")
    only = ap.add_mutually_exclusive_group()
    only.add_argument("--for-user", metavar="USER",
                      help="only this user (id, username, email or name): their roles, groups and privileges")
    only.add_argument("--for-role", metavar="ROLE",
                      help="only this role (id or name): its privileges and the users and groups holding it")
    ap.add_argument("-o", "--output", default="-", help="output file (default: stdout)")
    args = ap.parse_args(argv)

    if not urlsplit(args.url).scheme:
        args.url = "https://" + args.url
    token = args.token or (None if args.user else os.environ.get("XO_TOKEN"))
    password = None
    if args.user:
        password = os.environ.get("XO_PASSWORD") or getpass.getpass("password for %s: " % args.user)
    elif not token:
        ap.error("no credentials: pass --token, set $XO_TOKEN, or use --user")

    client = Client(args.url, token=token, user=args.user, password=password, insecure=args.insecure)
    try:
        data = fetch(client)
        model = build(data)
        admin_visible = any(u["admin"] for u in model["users"])
        if args.for_user is not None:
            model = focus_user(model, find_user(data["users"], args.for_user)["id"])
        elif args.for_role is not None:
            model = focus_role(model, find_role(data["roles"], args.for_role)["id"])
        if args.server_effective:
            data["server_effective"] = fetch_effective(client, [u["id"] for u in model["users"]])
            for u in model["users"]:
                u["serverEffective"] = data["server_effective"][u["id"]]
    except ApiError as e:
        print("rbac-dump: %s" % e, file=sys.stderr)
        return 1

    if args.json and args.raw:
        text = json.dumps(dict(data, tool=NAME, version=VERSION), indent=2, sort_keys=True) + "\n"
    else:
        if not admin_visible:
            model["warnings"].insert(0, "no admin user is visible: this login is probably not an admin, "
                                        "so the dump only shows what it may read")
        if args.json:
            text = json.dumps(dict(model, source=args.url, tool=NAME, version=VERSION),
                              indent=2, sort_keys=True) + "\n"
        else:
            text = render(model, args.url, args.templates)

    if args.output == "-":
        sys.stdout.write(text)
    else:
        with open(args.output, "w") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
