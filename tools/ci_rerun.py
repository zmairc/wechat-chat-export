"""CI 辅助脚本：查看运行状态、重跑失败的任务、把失败日志抓下来。

只依赖标准库。令牌按这个顺序找：

1. `--token`
2. 环境变量 `GITHUB_TOKEN` / `GH_TOKEN`
3. `git credential fill`（走系统凭据管理器，**令牌不会被打印**）

用法：

```bash
python tools/ci_rerun.py status                    # 最近 5 次运行
python tools/ci_rerun.py rerun --run 40165063751   # 只重跑失败的任务
python tools/ci_rerun.py watch --run 40165063751   # 盯着跑，直到结束
python tools/ci_rerun.py logs  --run 40165063751   # 抓失败 job 的日志（自动挑失败行）
python tools/ci_rerun.py logs  --run <id> --job 3.12 --full   # 只看某个矩阵腿，输出完整日志
```

它只做三件事：读状态、发一个 rerun 请求、把日志文本打出来。不改仓库、不动代码。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"

# 日志里值得单独拎出来的行
INTERESTING = re.compile(
    r"(FAIL|Traceback|Error|error:|Exception|assert|AssertionError|"
    r"exit code|UnicodeEncode|Permission|denied)",
    re.IGNORECASE,
)


def force_utf8_stdio() -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


# ------------------------------------------------------------------ 凭据

def token_from_git_credential() -> str | None:
    """从系统凭据管理器取 github.com 的令牌（Git Credential Manager 等）。"""
    try:
        proc = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in proc.stdout.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip() or None
    return None


def resolve_token(explicit: str | None) -> str:
    token = explicit or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token.strip()
    token = token_from_git_credential()
    if token:
        return token
    raise SystemExit(
        "找不到 GitHub 令牌。可用 --token、环境变量 GITHUB_TOKEN，"
        "或先让 git 登录一次（git credential fill 能返回密码即可）。"
    )


# ------------------------------------------------------------------ 仓库

def repo_slug(explicit: str | None) -> str:
    if explicit:
        return explicit
    try:
        url = subprocess.run(["git", "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=15).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        url = ""
    m = re.search(r"github\.com[:/]+([^/]+)/([^/\s]+?)(?:\.git)?$", url)
    if not m:
        raise SystemExit("推断不出仓库（origin 不是 github 地址），请用 --repo owner/name")
    return f"{m.group(1)}/{m.group(2)}"


# ------------------------------------------------------------------ HTTP

class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """日志下载会 302 到签名 URL，那边不认 Authorization 头，重定向时去掉。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.headers.pop("Authorization", None)
        return new


_OPENER = urllib.request.build_opener(_StripAuthOnRedirect)


def call(method: str, path: str, token: str, payload=None, raw: bool = False,
         timeout: int = 60):
    url = path if path.startswith("http") else API + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "wxchat-export-ci-helper")
    req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        hint = ""
        if e.code in (401, 403):
            hint = "\n提示：令牌可能没有 actions:write 权限（细粒度 PAT 需要 Actions 读写）。"
        raise SystemExit(f"HTTP {e.code} {method} {url}\n{detail}{hint}") from None
    if raw:
        return body.decode("utf-8", "replace")
    return json.loads(body) if body else {}


# ------------------------------------------------------------------ 子命令

def _runs(token: str, repo: str, limit: int = 8) -> list[dict]:
    data = call("GET", f"/repos/{repo}/actions/runs?per_page={limit}", token)
    return data.get("workflow_runs", [])


def _jobs(token: str, repo: str, run_id: int) -> list[dict]:
    data = call("GET", f"/repos/{repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100", token)
    return data.get("jobs", [])


def _pick_run(token: str, repo: str, explicit: int | None, failed: bool) -> dict:
    if explicit:
        return call("GET", f"/repos/{repo}/actions/runs/{explicit}", token)
    for run in _runs(token, repo):
        if failed and run.get("conclusion") in ("failure", "timed_out", "cancelled"):
            return run
        if not failed:
            return run
    raise SystemExit("最近几次运行里没有失败记录，用 --run 指定具体 run id 吧。")


def cmd_status(args, token: str, repo: str) -> int:
    for run in _runs(token, repo, args.limit):
        print(f"{run['id']}  {run['conclusion'] or run['status']:10s}  "
              f"{run['head_branch']:10s}  {run['created_at']}  {run['display_title'][:50]}")
    return 0


def cmd_rerun(args, token: str, repo: str) -> int:
    run = _pick_run(token, repo, args.run, failed=not args.run)
    run_id = run["id"]
    print(f"[*] 目标运行：{run_id}  {run.get('display_title', '')[:60]}")
    jobs = _jobs(token, repo, run_id)
    failed = [j for j in jobs if j.get("conclusion") not in (None, "success", "skipped")]
    for j in jobs:
        print(f"    {j['name']:24s} {j.get('conclusion')}")
    if not failed and not args.all:
        print("[*] 这次运行没有失败的任务；要整个重跑请加 --all")
        return 0

    if args.all:
        call("POST", f"/repos/{repo}/actions/runs/{run_id}/rerun", token, payload={})
        print("[+] 已请求：整条运行重跑")
    else:
        call("POST", f"/repos/{repo}/actions/runs/{run_id}/rerun-failed-jobs", token, payload={})
        print(f"[+] 已请求：重跑失败任务（{', '.join(j['name'] for j in failed)}）")
    if args.watch:
        return cmd_watch(args, token, repo, run_id=run_id)
    return 0


def cmd_watch(args, token: str, repo: str, run_id: int | None = None) -> int:
    run_id = run_id or _pick_run(token, repo, args.run, failed=False)["id"]
    print(f"[*] 等待运行 {run_id} 结束（每 {args.interval}s 查一次，Ctrl+C 可中断）")
    last = ""
    while True:
        run = call("GET", f"/repos/{repo}/actions/runs/{run_id}", token)
        line = f"{run['status']}/{run.get('conclusion') or '-'}"
        if line != last:
            print(f"    {time.strftime('%H:%M:%S')}  {line}")
            last = line
        if run["status"] == "completed":
            print(f"[*] 结果：{run.get('conclusion')}   详情：{run['html_url']}")
            if getattr(args, "log_on_finish", True) and run.get("conclusion") != "success":
                print()
                return cmd_logs(argparse.Namespace(run=run_id, job=None, full=False,
                                                   grep=None, repo=repo, token=args.token), token, repo)
            return 0 if run.get("conclusion") == "success" else 1
        time.sleep(args.interval)


def cmd_logs(args, token: str, repo: str) -> int:
    run = _pick_run(token, repo, args.run, failed=False)
    run_id = run["id"]
    jobs = _jobs(token, repo, run_id)
    targets = [j for j in jobs if j.get("conclusion") not in (None, "success", "skipped")]
    if args.job:
        targets = [j for j in jobs if re.search(args.job, j["name"])]
    if not targets:
        print("[*] 没有失败任务可看；要看全部请加 --job .")
        return 0
    for j in targets:
        print("=" * 70)
        print(f"# {j['name']}  ({j.get('conclusion')})   job {j['id']}")
        print("=" * 70)
        text = call("GET", f"/repos/{repo}/actions/jobs/{j['id']}/logs", token, raw=True)
        print_log(text, full=args.full, job_name=j["name"])
    return 0


def print_log(text: str, full: bool, job_name: str = "") -> None:
    lines = text.splitlines()
    if full:
        print("\n".join(lines[-800:]))
        return
    hits = [ln for ln in lines if INTERESTING.search(ln)]
    # GitHub 的日志每行带时间戳前缀，去掉更清爽
    strip = lambda s: re.sub(r"^\d{4}-\d\d-\d\dT[\d:.]+Z\s*", "", s)
    if hits:
        print("--- 命中的行 ---")
        for ln in hits[:60]:
            print(strip(ln))
    print("\n--- 末尾 40 行 ---")
    for ln in lines[-40:]:
        print(strip(ln))


# ------------------------------------------------------------------ 入口

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GitHub Actions：查看 / 重跑 / 抓日志")
    ap.add_argument("--token", help="GitHub 令牌（默认走环境变量或系统凭据管理器）")
    ap.add_argument("--repo", help="owner/name（默认从 git remote origin 推断）")

    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("status", help="最近几次运行")
    p.add_argument("--limit", type=int, default=5)

    p = sub.add_parser("rerun", help="重跑失败任务")
    p.add_argument("--run", type=int, help="run id（默认取最近一次失败的）")
    p.add_argument("--all", action="store_true", help="整条运行重跑，而不是只重跑失败任务")
    p.add_argument("--watch", action="store_true", help="重跑后盯着直到结束")
    p.add_argument("--interval", type=int, default=10)

    p = sub.add_parser("watch", help="盯着某次运行直到结束")
    p.add_argument("--run", type=int)
    p.add_argument("--interval", type=int, default=10)
    p.add_argument("--log-on-finish", action="store_true", default=True,
                   help="结束时如果失败就顺手抓日志（默认开）")

    p = sub.add_parser("logs", help="抓失败 job 的日志")
    p.add_argument("--run", type=int)
    p.add_argument("--job", help="按 job 名过滤（正则，比如 3.12）")
    p.add_argument("--full", action="store_true", help="输出完整日志而不只是命中行")
    p.add_argument("--grep")

    args = ap.parse_args(argv)
    force_utf8_stdio()
    if not args.cmd:
        args.cmd = "status"
        args.limit = 5

    token = resolve_token(args.token)
    repo = repo_slug(args.repo)

    table = {"status": cmd_status, "rerun": cmd_rerun,
             "watch": cmd_watch, "logs": cmd_logs}
    return table[args.cmd](args, token, repo)


if __name__ == "__main__":
    sys.exit(main())
