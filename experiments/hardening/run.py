"""Phase 10 hardening checks. Raw tool output goes to experiments/hardening/results/; each
finding is fixed or documented in docs/gateway/research/hardening.md.

    uv run python -m experiments.hardening.run scans     # pip-audit, npm audit, bandit, semgrep,
                                                         # gitleaks, trivy, slither
    uv run python -m experiments.hardening.run ci        # the CI subset (no Docker scanners)
    uv run python -m experiments.hardening.run grants    # DB least-privilege review
    uv run python -m experiments.hardening.run backup    # pg_dump -> restore -> verify drill

Scanner versions are pinned here; the summary records the version each run used.
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from experiments.lib.common import REPO, environment, results_dir, write_csv, write_json

HERE = Path(__file__).resolve().parent
PIP_AUDIT = "pip-audit@2.9.0"
BANDIT = "bandit@1.8.3"
SEMGREP = "semgrep@1.119.0"
GITLEAKS = "zricethezav/gitleaks:v8.21.2"
TRIVY = "aquasec/trivy:0.58.1"
IMAGES = ["agw-ui-gateway:latest", "agw-ui-dashboard:latest", "agw-containment-agent:latest"]
DUMP_DIR_IN_CONTAINER = "/var/lib/postgresql"  # inside the throwaway Postgres containers
DUMP_IN_CONTAINER = f"{DUMP_DIR_IN_CONTAINER}/agw.dump"
SRC = ["apps/gateway/src", "apps/worker/src", "packages/gateway-sdk/src", "packages/schemas/src",
       "packages/verifier/src", "integrations/langgraph/src", "integrations/mcp/src"]  # fmt: skip


def sh(
    argv: list[str], *, cwd: Path = REPO, timeout: int = 1800
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, cwd=cwd, capture_output=True, text=True, check=False, timeout=timeout
    )


def pip_audit(out: Path) -> dict[str, Any]:
    req = out / "requirements-frozen.txt"
    r = sh(["uv", "export", "--frozen", "--no-hashes", "--no-emit-workspace", "--all-packages",
            "--all-extras", "-o", str(req)])  # fmt: skip
    assert r.returncode == 0, r.stderr
    p = sh(["uvx", PIP_AUDIT, "-r", str(req), "--format", "json", "--disable-pip", "--no-deps"])
    (out / "pip-audit.json").write_text(p.stdout or p.stderr)
    try:
        deps = json.loads(p.stdout)["dependencies"]
    except (ValueError, KeyError):
        return {"tool": PIP_AUDIT, "status": "ERROR", "detail": p.stderr[-300:]}
    vulns = [(d["name"], d["version"], v["id"], ",".join(v.get("fix_versions", [])))
             for d in deps for v in d.get("vulns", [])]  # fmt: skip
    return {"tool": PIP_AUDIT, "status": "OK", "packages": len(deps), "findings": len(vulns),
            "detail": "; ".join(f"{n} {v} {i} fix:{f or '-'}" for n, v, i, f in vulns)}  # fmt: skip


def npm_audit(out: Path) -> dict[str, Any]:
    p = sh(["npm", "audit", "--json"], cwd=REPO / "apps" / "dashboard")
    (out / "npm-audit.json").write_text(p.stdout)
    try:
        meta = json.loads(p.stdout)["metadata"]["vulnerabilities"]
        vulns = json.loads(p.stdout)["vulnerabilities"]
    except (ValueError, KeyError):
        return {"tool": "npm audit", "status": "ERROR", "detail": p.stderr[-300:]}
    return {"tool": "npm audit", "status": "OK", "findings": meta.get("total", 0),
            "detail": "; ".join(f"{k} ({v['severity']})" for k, v in vulns.items())}  # fmt: skip


def bandit(out: Path) -> dict[str, Any]:
    p = sh(["uvx", "--python", "3.13", BANDIT, "-r", *SRC, "-f", "json", "-q"])
    (out / "bandit.json").write_text(p.stdout)
    try:
        res = json.loads(p.stdout)["results"]
    except (ValueError, KeyError):
        return {"tool": BANDIT, "status": "ERROR", "detail": p.stderr[-300:]}
    sev: dict[str, int] = {}
    for r in res:
        sev[r["issue_severity"]] = sev.get(r["issue_severity"], 0) + 1
    return {"tool": BANDIT, "status": "OK", "findings": len(res),
            "detail": json.dumps(sev) + " | " + "; ".join(sorted({f"{r['test_id']}:{r['filename']}:{r['line_number']}"
                                                                    for r in res if r["issue_severity"] != "LOW"}))}  # fmt: skip


def semgrep(out: Path) -> dict[str, Any]:
    p = sh(["uvx", SEMGREP, "scan", "--config", "p/python", "--config", "p/secrets", "--json",
            "--metrics", "off", "--quiet", *SRC])  # fmt: skip
    (out / "semgrep.json").write_text(p.stdout or p.stderr)
    try:
        res = json.loads(p.stdout)["results"]
    except (ValueError, KeyError):
        return {"tool": SEMGREP, "status": "ERROR", "detail": (p.stderr or p.stdout)[-300:]}
    return {"tool": SEMGREP, "status": "OK", "findings": len(res),
            "detail": "; ".join(sorted({f"{r['check_id'].split('.')[-1]}:{r['path']}:{r['start']['line']}"
                                        for r in res}))}  # fmt: skip


def gitleaks(out: Path) -> dict[str, Any]:
    rep = out / "gitleaks.json"
    p = sh(["docker", "run", "--rm", "-v", f"{REPO}:/repo:ro", "-v", f"{out}:/out", GITLEAKS,
            "detect", "--no-git", "--source", "/repo", "--report-format", "json",
            "--report-path", "/out/gitleaks.json", "--redact", "--no-banner"])  # fmt: skip
    try:
        res = json.loads(rep.read_text())
    except (OSError, ValueError):
        return {"tool": GITLEAKS, "status": "ERROR", "detail": p.stderr[-300:]}
    return {"tool": GITLEAKS, "status": "OK", "findings": len(res),
            "detail": "; ".join(sorted({f"{r['RuleID']}:{r['File']}:{r['StartLine']}" for r in res}))}  # fmt: skip


def trivy(out: Path) -> list[dict[str, Any]]:
    rows = []
    for image in IMAGES:
        name = image.split(":")[0]
        p = sh(["docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", "agw-trivy-cache:/root/.cache", TRIVY, "image", "--quiet", "--format", "json",
                "--scanners", "vuln", "--severity", "HIGH,CRITICAL", image], timeout=3600)  # fmt: skip
        (out / f"trivy-{name}.json").write_text(p.stdout or p.stderr)
        try:
            results = json.loads(p.stdout).get("Results") or []
        except ValueError:
            rows.append({"tool": f"{TRIVY} {image}", "status": "ERROR", "detail": p.stderr[-300:]})
            continue
        vulns = [v for r in results for v in (r.get("Vulnerabilities") or [])]
        by = {}
        for v in vulns:
            by[v["Severity"]] = by.get(v["Severity"], 0) + 1
        fixable = sorted(
            {f"{v['PkgName']} {v['VulnerabilityID']}" for v in vulns if v.get("FixedVersion")}
        )
        rows.append({"tool": f"{TRIVY} {image}", "status": "OK", "findings": len(vulns),
                     "detail": json.dumps(by) + f" | fixable: {len(fixable)}: " + "; ".join(fixable[:40])})  # fmt: skip
    return rows


def slither(out: Path) -> dict[str, Any]:
    p = sh(["make", "contracts-slither"], timeout=3600)
    (out / "slither.txt").write_text(p.stdout + p.stderr)
    found = [ln for ln in (p.stdout + p.stderr).splitlines() if "result(s) found" in ln]
    return {"tool": "slither (make contracts-slither)", "status": "OK" if p.returncode in (0, 1, 255) else "ERROR",
            "findings": found[-1] if found else "?", "detail": f"exit {p.returncode}"}  # fmt: skip


def scans(ci_only: bool) -> int:
    out = results_dir(HERE)
    rows = [pip_audit(out), npm_audit(out), bandit(out)]
    if not ci_only:
        rows += [semgrep(out), gitleaks(out), *trivy(out), slither(out)]
    for r in rows:
        print(f"{r['tool']}: {r['status']} findings={r.get('findings')}", flush=True)
    write_csv(out / ("scans-ci.csv" if ci_only else "scans.csv"), rows,
              ["tool", "status", "packages", "findings", "detail"])  # fmt: skip
    if ci_only:  # CI fails on any known-vulnerable dependency or a medium/high bandit finding
        bad = [
            r for r in rows if r["status"] != "OK" or (r["tool"] != BANDIT and r.get("findings"))
        ]
        bad += [
            r
            for r in rows
            if r["tool"] == BANDIT and ('"MEDIUM"' in r["detail"] or '"HIGH"' in r["detail"])
        ]
        return 1 if bad else 0
    return 0


# --------------------------------------------------------------------------- DB grants review
APPEND_ONLY = {"evidence_events", "epochs", "approval_decisions", "anchors", "monitor_reports",
               "delegation_uses"}  # fmt: skip


def grants() -> int:
    import psycopg

    from experiments.lib.stack import postgres

    out = results_dir(HERE)
    with postgres() as urls, psycopg.connect(urls.superuser) as conn:
        roles = conn.execute(
            "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolinherit "
            "FROM pg_roles WHERE rolname LIKE 'agw%' ORDER BY 1").fetchall()  # fmt: skip
        owned = conn.execute(
            "SELECT tableowner, count(*) FROM pg_tables WHERE schemaname='public' GROUP BY 1"
        ).fetchall()
        tg = conn.execute(
            "SELECT table_name, string_agg(privilege_type, ',' ORDER BY privilege_type) "
            "FROM information_schema.role_table_grants WHERE grantee='agw_app' AND table_schema='public' "
            "GROUP BY 1 ORDER BY 1").fetchall()  # fmt: skip
        cols = conn.execute(
            "SELECT table_name, privilege_type, string_agg(column_name, ',' ORDER BY column_name) "
            "FROM information_schema.column_privileges WHERE grantee='agw_app' AND table_schema='public' "
            "AND table_name NOT IN (SELECT table_name FROM information_schema.role_table_grants "
            "  WHERE grantee='agw_app' AND table_schema='public' AND privilege_type=column_privileges.privilege_type) "
            "GROUP BY 1, 2 ORDER BY 1, 2").fetchall()  # fmt: skip
        triggers = conn.execute(
            "SELECT event_object_table, string_agg(DISTINCT event_manipulation, ',') FROM "
            "information_schema.triggers WHERE trigger_schema='public' GROUP BY 1 ORDER BY 1").fetchall()  # fmt: skip
        funcs = conn.execute(
            "SELECT p.proname, p.prosecdef FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='public' ORDER BY 1").fetchall()  # fmt: skip
        tables = [r[0] for r in conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1")]  # fmt: skip
    table_grants = dict(tg)
    trig = dict(triggers)
    rows, flags = [], []
    for tname in tables:
        privs = table_grants.get(tname, "")
        rows.append({"table": tname, "agw_app_table_privileges": privs,
                     "agw_app_column_privileges": "; ".join(f"{p}({c})" for t_, p, c in cols if t_ == tname),
                     "triggers_on": trig.get(tname, "")})  # fmt: skip
        for bad in ("TRUNCATE", "TRIGGER", "REFERENCES"):
            if bad in privs.split(","):
                flags.append(f"{tname}: agw_app has {bad}")
        if (
            tname in APPEND_ONLY
            and ({"UPDATE", "DELETE"} & set(privs.split(",")))
            and "UPDATE" not in trig.get(tname, "")
        ):
            flags.append(
                f"{tname}: append-only table writable by agw_app without a guarding trigger"
            )
    for r in roles:
        if r[0] == "agw_app" and any(r[1:5]):
            flags.append(f"agw_app has elevated role attributes {r}")
    for owner, n in owned:
        if owner == "agw_app":
            flags.append(f"agw_app owns {n} tables (could disable triggers)")
    for name, secdef in funcs:
        if secdef:
            flags.append(f"SECURITY DEFINER function {name} (review)")
    write_csv(out / "db-grants.csv", rows)
    write_json(out / "db-grants.json", {"roles": [list(r) for r in roles], "table_owners": [list(o) for o in owned],
                                         "security_definer_functions": [f for f, s in funcs if s],
                                         "flags": flags})  # fmt: skip
    print(json.dumps({"flags": flags}, indent=1))
    return 0


# --------------------------------------------------------------------------- backup/restore drill
def backup() -> int:
    """Populate a DB through the gateway (actions, approvals, sealed epochs + an unsealed
    tail), pg_dump it (custom format, as an operator would), restore into a NEW Postgres,
    then: the independent verifier on exports from BOTH, identical chain heads, identical
    epoch roots, append-only triggers still enforced in the restored copy."""
    import psycopg
    from fastapi.testclient import TestClient
    from tests.conftest import start_postgres

    from agw_gateway.api.app import create_app
    from agw_gateway.evidence.bundle import export_epochs
    from agw_gateway.evidence.export import export_chain
    from agw_verifier.chain import verify_lines
    from agw_verifier.epochs import verify_epochs
    from agw_worker.sealing import Sealer
    from agw_worker.sealing.policy import SealPolicy
    from experiments.lib.stack import gateway, postgres_container

    out = results_dir(HERE)
    work = Path(tempfile.mkdtemp(prefix="agw-backup-"))
    report: dict[str, Any] = {}

    def exports(engine: Any, tenant: str) -> tuple[str, str]:
        ev, ep = io.StringIO(), io.StringIO()
        export_chain(engine, tenant, ev)
        with engine.connect() as c:
            export_epochs(c, tenant, ep)
        return ev.getvalue(), ep.getvalue()

    with (
        postgres_container() as (src, urls),
        gateway(urls, ablation=None, rate_limit_per_minute=0) as gw,
    ):
        with TestClient(create_app(gw.state, sync_registry=False)) as c:
            h = {"Authorization": f"Bearer {gw.token}"}
            for i in range(150):
                tool, args = [("test_echo", {"text": "b"}), ("create_ticket", {"title": "b"}),
                              ("send_email", {"to": ["x@partner.example"], "subject": "s"})][i % 3]  # fmt: skip
                c.post("/v1/actions", headers={**h, "Idempotency-Key": f"b{i}"},
                       json={"run_id": "00000000-0000-0000-0000-0000000000b0", "tool": tool,
                             "environment": "dev", "args": args})  # fmt: skip
            while gw.state.executor.run_once():
                pass
            Sealer(engine=gw.engine, writer=gw.state.writer, crash=gw.state.crash,
                   policy=SealPolicy.fixed(100, 0.0)).drain()  # fmt: skip
            for i in range(5):
                c.post("/v1/actions", headers={**h, "Idempotency-Key": f"t{i}"},
                       json={"run_id": "00000000-0000-0000-0000-0000000000b0", "tool": "test_echo",
                             "environment": "dev", "args": {"text": "tail"}})  # fmt: skip
            while gw.state.executor.run_once():
                pass
        ev_src, ep_src = exports(gw.engine, gw.tenant)
        dump = work / "agw.dump"
        wrapped = src.get_wrapped_container()
        r = wrapped.exec_run(
            ["pg_dump", "-U", "postgres", "-d", "agw", "-Fc", "-f", DUMP_IN_CONTAINER]
        )
        assert r.exit_code == 0, r.output
        bits, _ = wrapped.get_archive(DUMP_IN_CONTAINER)
        import tarfile

        tar_path = work / "dump.tar"
        tar_path.write_bytes(b"".join(bits))
        with tarfile.open(tar_path) as tf:
            tf.extract("agw.dump", work, filter="data")
        report["dump_bytes"] = dump.stat().st_size
        tenant = gw.tenant
    dst = start_postgres()
    try:
        w = dst.get_wrapped_container()
        import tarfile as _tf

        buf = io.BytesIO()
        with _tf.open(fileobj=buf, mode="w") as tf:
            tf.add(dump, arcname="agw.dump")
        w.put_archive(DUMP_DIR_IN_CONTAINER, buf.getvalue())
        for role in ("agw_migrator", "agw_app"):  # roles are cluster objects: not in pg_dump
            w.exec_run(["psql", "-U", "postgres", "-c", f"CREATE ROLE {role} LOGIN"])
        r = w.exec_run(
            ["pg_restore", "-U", "postgres", "-d", "agw", "--exit-on-error", DUMP_IN_CONTAINER]
        )
        report["pg_restore_exit"] = r.exit_code
        assert r.exit_code == 0, r.output[-2000:]
        from sqlalchemy import create_engine

        host, port = dst.get_container_host_ip(), dst.get_exposed_port(5432)
        su = f"postgresql+psycopg://postgres:{dst.password}@{host}:{port}/agw"
        eng = create_engine(su)
        ev_dst, ep_dst = exports(eng, tenant)
        eng.dispose()
        ch_src, ch_dst = verify_lines(ev_src.splitlines()), verify_lines(ev_dst.splitlines())
        e_src = verify_epochs(ep_src.splitlines(), event_lines=ev_src.splitlines())
        e_dst = verify_epochs(ep_dst.splitlines(), event_lines=ev_dst.splitlines())
        report.update({
            "events": ch_dst.events_checked, "chain_source": ch_src.result, "chain_restored": ch_dst.result,
            "epochs_source": e_src.result, "epochs_restored": e_dst.result,
            "same_chain_head": (ch_src.last_seq, ch_src.last_hash) == (ch_dst.last_seq, ch_dst.last_hash),
            "same_epoch_roots": (e_src.last_epoch_no, e_src.last_epoch_root) == (e_dst.last_epoch_no, e_dst.last_epoch_root),
            "exports_identical": ev_src == ev_dst and ep_src == ep_dst,
        })  # fmt: skip
        with psycopg.connect(f"host={host} port={port} dbname=agw user=postgres password={dst.password}",
                             autocommit=True) as conn:  # fmt: skip
            try:
                conn.execute("UPDATE evidence_events SET seq = seq WHERE seq = 0")
                report["append_only_trigger_restored"] = False
            except psycopg.Error as exc:
                report["append_only_trigger_restored"] = True
                report["append_only_error"] = str(exc).splitlines()[0][:160]
    finally:
        dst.stop()
    ok = all(report[k] for k in ("same_chain_head", "same_epoch_roots", "exports_identical",
                                 "append_only_trigger_restored")) and report["chain_restored"] == "VERIFIED"  # fmt: skip
    report["drill_passed"] = ok
    write_json(out / "backup-drill.json", report)
    print(json.dumps(report, indent=1))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["scans", "ci", "grants", "backup"])
    a = ap.parse_args()
    if a.what in ("scans", "ci"):
        rc = scans(ci_only=a.what == "ci")
    elif a.what == "grants":
        rc = grants()
    else:
        rc = backup()
    write_json(results_dir(HERE) / f"env-{a.what}.json", environment({}))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
