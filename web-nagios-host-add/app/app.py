import os
import re
import fcntl
import subprocess
import html
from string import Template
from functools import wraps
from flask import Flask, request, Response, redirect

AUTH_USER = os.getenv("AUTH_USER", "admin")
AUTH_PASS = os.getenv("AUTH_PASS", "change-me")
CFG_FILE  = os.getenv("CFG_FILE", "/data/promoteuksites.cfg")
RESTART_NAGIOS = os.getenv("RESTART_NAGIOS", "false").lower() == "true"
NAGIOS_CONTAINER = os.getenv("NAGIOS_CONTAINER", "").strip()

app = Flask(__name__)

# Strict bare-domain validator
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

def check_auth(username, password):
    return username == AUTH_USER and password == AUTH_PASS

def authenticate():
    return Response(
        "Authentication required.\n",
        401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'},
    )

def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return wrapper

def clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)  # strip scheme
    d = d.split("/")[0]               # strip path
    d = d.split(":")[0]               # strip port
    return d

def host_exists(cfg_text: str, domain: str) -> bool:
    pat = re.compile(
        r"define\s+host\s*\{[^}]*\bhost_name\s+" + re.escape(domain) + r"\b[^}]*\}",
        re.IGNORECASE | re.DOTALL
    )
    return pat.search(cfg_text) is not None

def count_blocks(cfg_text: str, domain: str):
    host_pat = re.compile(
        r"define\s+host\s*\{[^}]*\bhost_name\s+" + re.escape(domain) + r"\b[^}]*\}",
        re.IGNORECASE | re.DOTALL
    )
    svc_pat = re.compile(
        r"define\s+service\s*\{[^}]*\bhost_name\s+" + re.escape(domain) + r"\b[^}]*\}",
        re.IGNORECASE | re.DOTALL
    )
    hosts = list(host_pat.finditer(cfg_text))
    svcs  = list(svc_pat.finditer(cfg_text))
    return hosts, svcs

def remove_blocks(cfg_text: str, domain: str):
    hosts, svcs = count_blocks(cfg_text, domain)
    spans = [m.span() for m in hosts] + [m.span() for m in svcs]
    if not spans:
        return cfg_text, 0, 0
    spans.sort(key=lambda s: s[0], reverse=True)
    out = cfg_text
    for a, b in spans:
        out = out[:a] + out[b:]
    # tidy excessive blank lines
    out = re.sub(r"\n{3,}", "\n\n", out).strip() + "\n"
    return out, len(hosts), len(svcs)

def build_block(domain: str) -> str:
    # EXACT template; only host_name/alias/address use the submitted domain.
    return f"""define host{{
        use                     promoteuk-host
        host_name               {domain}
        alias                   {domain}
        address                 {domain}
        }}
define service{{
        use                     promoteuk-service
        host_name               {domain}
        service_description     SSL CERT
        check_command           check_ssl_status
        servicegroups           sslcertcheck
        }}
define service{{
        use                     promoteuk-service
        host_name               {domain}
        service_description     DNS A RECORD
        check_command           check_ip_nameserver
        servicegroups           dnsrecordcheck
        }}
define service{{
        use                     promoteuk-service-expiry
        host_name               {domain}
        service_description     Domain Expiry
        check_command           check_expiry_reg
        servicegroups           domainexpirycheck
        }}
define service{{
        use                     promoteuk-service-matchip
        host_name               {domain}
        service_description     DNS Change to 109.123.111.20 URGENT
        check_command           check_matchip_109_123_111_20
        servicegroups           match_109_123_111_20
        }}

"""

def restart_nagios_container():
    """Try to restart via Docker SDK first; else try docker CLI; never raise."""
    if not RESTART_NAGIOS or not NAGIOS_CONTAINER:
        return (False, "Restart disabled or NAGIOS_CONTAINER not set.")
    # Try Python Docker SDK
    try:
        import docker  # type: ignore
        try:
            client = docker.from_env()
            c = client.containers.get(NAGIOS_CONTAINER)
            c.restart()
            return (True, f"Restarted container '{html.escape(NAGIOS_CONTAINER)}'.")
        except Exception as e:
            sdk_err = str(e)
    except Exception as e:
        sdk_err = str(e)

    # Fallback to docker CLI
    try:
        subprocess.run(["docker", "restart", NAGIOS_CONTAINER], check=True, capture_output=True)
        return (True, f"Restarted container '{html.escape(NAGIOS_CONTAINER)}' via CLI.")
    except FileNotFoundError:
        return (False, f"Cannot restart: docker SDK failed ({html.escape(sdk_err)}), and docker CLI not present in container.")
    except subprocess.CalledProcessError as e:
        return (False, f"CLI restart failed: {html.escape(e.stderr.decode('utf-8', errors='ignore'))}")

HTML_FORM = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Nagios Host Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding: 24px; max-width: 800px; margin: 0 auto; }
  h1 { margin-bottom: 8px; }
  h2 { margin-top: 24px; }
  form { display: grid; gap: 12px; margin-top: 12px; max-width: 520px; }
  input[type=text] { padding: 10px; font-size: 16px; }
  button { padding: 10px 14px; font-size: 15px; cursor: pointer; }
  .row { display:flex; gap:12px; align-items:center; }
  .msg { margin-top: 16px; padding: 12px; border-radius: 8px; }
  .ok { background: #e6ffed; border: 1px solid #b7f5c5; }
  .warn { background: #fff7e6; border: 1px solid #ffe0a3; }
  .err { background: #ffecec; border: 1px solid #ffbdbd; }
  code { background: #f6f8fa; padding: 2px 6px; border-radius: 4px; }
</style>
</head>
<body>
  <h1>Nagios Host Admin</h1>
  <p>Checks and updates <code>$cfg_file</code>. Add flow asks for confirmation if host not found. Remove flow asks for confirmation before deleting.</p>

  <h2>Add Host</h2>
  <form method="POST" action="/submit">
    <label for="domain-add">Domain name</label>
    <input id="domain-add" name="domain" type="text" placeholder="example.com" required>
    <button type="submit">Check</button>
  </form>

  <h2>Remove Host</h2>
  <form method="POST" action="/remove">
    <label for="domain-rem">Domain name</label>
    <input id="domain-rem" name="domain" type="text" placeholder="example.com" required>
    <button type="submit">Check</button>
  </form>

  $message

  <p style="margin-top:28px;font-size:12px;color:#666;">
    Config file: <code>$cfg_file</code>
  </p>
</body>
</html>
""")

def render(message_html=""):
    return HTML_FORM.safe_substitute(message=message_html, cfg_file=CFG_FILE)

@app.route("/", methods=["GET"])
@requires_auth
def home():
    return render()

@app.route("/submit", methods=["POST"])
@requires_auth
def submit():
    raw = request.form.get("domain", "")
    confirm = request.form.get("confirm", "no")
    domain = clean_domain(raw)
    domain_esc = html.escape(domain)

    if not DOMAIN_RE.match(domain):
        return render(f'<div class="msg err">Invalid domain: <strong>{domain_esc}</strong></div>')

    try:
        with open(CFG_FILE, "a+", encoding="utf-8") as f:
            # Read check
            fcntl.lockf(f, fcntl.LOCK_EX)
            f.seek(0)
            cfg_data = f.read()
            exists = host_exists(cfg_data, domain)
            fcntl.lockf(f, fcntl.LOCK_UN)

            if exists:
                return render(f'<div class="msg warn">Host <strong>{domain_esc}</strong> already exists in config.</div>')

            # Not exists: ask to confirm adding
            if confirm != "yes":
                message = f"""
                <div class="msg warn">
                  Host <strong>{domain_esc}</strong> was <em>not found</em>.
                  Do you want to add it with the standard host + service blocks?
                  <form method="POST" action="/submit" class="row" style="margin-top:10px;">
                    <input type="hidden" name="domain" value="{domain_esc}">
                    <input type="hidden" name="confirm" value="yes">
                    <button type="submit">Confirm Add</button>
                    <a href="/" style="text-decoration:none;"><button type="button">Cancel</button></a>
                  </form>
                </div>
                """
                return render(message)

            # Confirmed add
            fcntl.lockf(f, fcntl.LOCK_EX)
            f.seek(0)
            cfg_data = f.read()
            if host_exists(cfg_data, domain):
                fcntl.lockf(f, fcntl.LOCK_UN)
                return render(f'<div class="msg warn">Host <strong>{domain_esc}</strong> already exists now (race condition).</div>')

            block = build_block(domain)
            if cfg_data and not cfg_data.endswith("\n"):
                f.write("\n")
            f.write(block)
            f.flush()
            os.fsync(f.fileno())
            fcntl.lockf(f, fcntl.LOCK_UN)

    except FileNotFoundError:
        return render(f'<div class="msg err">Config file not found: <code>{html.escape(CFG_FILE)}</code>. Check your volume mapping.</div>')
    except PermissionError:
        return render(f'<div class="msg err">Permission denied writing to <code>{html.escape(CFG_FILE)}</code>. Ensure the container has write access.</div>')
    except Exception as e:
        return render(f'<div class="msg err">Error: {html.escape(str(e))}</div>')

    ok, info = restart_nagios_container()
    css = "ok" if ok else "warn"
    restart_msg = f'<div class="msg {css}" style="margin-top:8px;">{info}</div>' if RESTART_NAGIOS else ""
    return render(f'<div class="msg ok">Added host and services for <strong>{domain_esc}</strong>.</div>{restart_msg}')

@app.route("/remove", methods=["POST"])
@requires_auth
def remove():
    raw = request.form.get("domain", "")
    confirm = request.form.get("confirm", "no")
    domain = clean_domain(raw)
    domain_esc = html.escape(domain)

    if not DOMAIN_RE.match(domain):
        return render(f'<div class="msg err">Invalid domain: <strong>{domain_esc}</strong></div>')

    try:
        with open(CFG_FILE, "r+", encoding="utf-8") as f:
            fcntl.lockf(f, fcntl.LOCK_EX)
            cfg_data = f.read()

            exists = host_exists(cfg_data, domain)
            if not exists:
                fcntl.lockf(f, fcntl.LOCK_UN)
                return render(f'<div class="msg warn">Host <strong>{domain_esc}</strong> was not found in the config.</div>')

            # Show confirmation with counts
            hosts, svcs = count_blocks(cfg_data, domain)
            if confirm != "yes":
                message = f"""
                <div class="msg warn">
                  Found <strong>{len(hosts)}</strong> host block and <strong>{len(svcs)}</strong> service block(s) for
                  <strong>{domain_esc}</strong>. Do you want to remove all of them?
                  <form method="POST" action="/remove" class="row" style="margin-top:10px;">
                    <input type="hidden" name="domain" value="{domain_esc}">
                    <input type="hidden" name="confirm" value="yes">
                    <button type="submit">Confirm Remove</button>
                    <a href="/" style="text-decoration:none;"><button type="button">Cancel</button></a>
                  </form>
                </div>
                """
                fcntl.lockf(f, fcntl.LOCK_UN)
                return render(message)

            # Confirmed: remove and write back
            new_text, host_count, svc_count = remove_blocks(cfg_data, domain)
            f.seek(0)
            f.truncate(0)
            f.write(new_text)
            f.flush()
            os.fsync(f.fileno())
            fcntl.lockf(f, fcntl.LOCK_UN)

    except FileNotFoundError:
        return render(f'<div class="msg err">Config file not found: <code>{html.escape(CFG_FILE)}</code>.</div>')
    except PermissionError:
        return render(f'<div class="msg err">Permission denied writing to <code>{html.escape(CFG_FILE)}</code>.</div>')
    except Exception as e:
        return render(f'<div class="msg err">Error: {html.escape(str(e))}</div>')

    ok, info = restart_nagios_container()
    css = "ok" if ok else "warn"
    restart_msg = f'<div class="msg {css}" style="margin-top:8px;">{info}</div>' if RESTART_NAGIOS else ""
    return render(f'<div class="msg ok">Removed <strong>{host_count}</strong> host block and <strong>{svc_count}</strong> service block(s) for <strong>{domain_esc}</strong>.</div>{restart_msg}')

@app.route("/favicon.ico")
def favicon():
    return redirect("data:,")
