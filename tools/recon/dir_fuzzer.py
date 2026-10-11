import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("recon.dir_fuzz")

COMMON_PATHS = [
    "admin", "administrator", "backup", "config", "conf", "db", "database",
    "log", "logs", "upload", "uploads", "download", "downloads",
    "api", "v1", "v2", "v3", "api/v1", "api/v2",
    ".git", ".env", ".svn", ".hg", ".DS_Store",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "wp-admin", "wp-content", "wp-includes", "wp-json",
    "phpinfo.php", "info.php", "test.php",
    "index.php", "index.html", "index.asp", "default.aspx",
    "login", "logout", "register", "signup", "signin",
    "dashboard", "panel", "cpanel", "whm",
    "manager", "management", "monitor", "status",
    "health", "healthcheck", "actuator", "actuator/health",
    "metrics", "prometheus", "grafana",
    "swagger", "swagger-ui", "api-docs", "api/documentation",
    "graphql", "graphiql", "playground",
    "ws", "wss", "socket.io", "sockjs",
    "static", "assets", "public", "dist", "build",
    "js", "css", "img", "images", "fonts",
    "template", "templates", "view", "views",
    "cache", "tmp", "temp", "data", "storage",
    "mail", "email", "contact", "feedback",
    "search", "suggest", "autocomplete",
    "proxy", "gateway", "tunnel", "relay",
    "webservice", "service", "services", "soap",
    "rest", "restful", "api/rest", "api/soap",
    "oauth", "oauth2", "oidc", "saml",
    "callback", "webhook", "hook",
    "test", "tests", "testing", "stage", "staging",
    "dev", "development", "local", "localhost",
    "beta", "alpha", "demo", "sandbox",
    "doc", "docs", "documentation", "readme",
    "changelog", "CHANGELOG", "CHANGES",
    "license", "LICENSE", "COPYING",
    "install", "setup", "configure", "migrate",
    "upgrade", "update", "patch", "fix",
    "report", "reports", "analytics", "statistics",
    "export", "import", "upload", "download",
    "xmlrpc.php", "wp-cron.php", "wp-login.php",
    "adm", "mod", "sys", "system", "shell",
    "cmd", "command", "exec", "run",
    "phpMyAdmin", "phpmyadmin", "pma",
    "server-status", "server-info",
    "cgi-bin", "cgi", "fcgi",
    ".aws", ".azure", ".gcp", ".credentials",
    "Dockerfile", "docker-compose.yml",
    "Jenkinsfile", ".travis.yml", ".gitlab-ci.yml",
    "composer.json", "composer.lock",
    "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "go.mod", "go.sum", "Cargo.toml",
    "build.gradle", "pom.xml", ".classpath",
    "web.xml", "application.properties",
    "application.yml", "bootstrap.properties",
    "log4j.properties", "log4j2.xml",
    "haproxy.cfg", "nginx.conf", ".htaccess",
    "config.php", "config.php.bak", "config.php.old",
    "database.php", "db.php", "conn.php",
    "settings.php", "wp-config.php",
    "config.js", "config.json", "config.yml",
    "local.xml", "core_config.php",
]

EXTENSIONS = ["", ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
              ".json", ".xml", ".yaml", ".yml", ".txt", ".html",
              ".bak", ".old", ".orig", ".swp", ".swo", ".save"]


def _test_path(base_url: str, path: str, sess: requests.Session,
               timeout: float, follow: bool = True) -> Optional[Dict]:
    if "://" in path:
        url = path
    else:
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        r = sess.get(url, timeout=timeout, allow_redirects=follow)
        if r.status_code != 404:
            size = len(r.content)
            ct = r.headers.get("Content-Type", "")
            return {
                "path": "/" + path.lstrip("/"),
                "status": r.status_code,
                "size": size,
                "content_type": ct.split(";")[0] if ct else "",
                "location": r.headers.get("Location", "") if r.status_code in (301, 302) else "",
                "body_hash": hashlib.md5(r.content or b"").hexdigest() if r.content else "",  # nosec B324 - fingerprint only
            }
    except requests.RequestException:
        pass
    return None


def _detect_catchall(base: str, sess: requests.Session,
                     timeout: float) -> Optional[int]:
    """返回 catch-all 响应的 md5 (int 化) 或 None.

    很多 SPA / 自定义错误处理器 / WAF 对任何未知路径都返回同样的 200 页面.
    如果不识别, dirfuzz 会把 200 个假路径全部当作发现, 污染下游测试点,
    导致真正的注入端点被挤出预算 (真实世界常见).

    探测两个几乎不可能存在的随机路径 + 一个明确的 404 路径:
    - 若两个随机路径返回同一 body => catch-all, 记录该 hash
    - 否则返回 None (正常服务器)
    """
    import random
    import string

    def _rand_path():
        return "/" + "".join(random.choices(string.ascii_lowercase + string.digits, k=24))

    hashes = []
    for _ in range(2):
        try:
            r = sess.get(base + _rand_path(), timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code in (404, 410):
            return None  # 正常 404 行为, 无 catch-all
        if r.status_code == 200 and r.content:
            hashes.append(hashlib.md5(r.content).hexdigest())  # nosec B324 - catch-all fingerprint

    if len(hashes) == 2 and hashes[0] == hashes[1]:
        return int(hashes[0], 16)
    return None


def fuzz_directories(url: str, wordlist: Optional[List[str]] = None,
                     extensions: Optional[List[str]] = None,
                     sess: Optional[requests.Session] = None,
                     threads: int = 20, timeout: float = 5.0,
                     max_results: int = 200,
                     follow_redirects: bool = True) -> Dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    words = wordlist or COMMON_PATHS
    exts = extensions or [""]
    base = url.rstrip("/")

    targets = []
    for w in words:
        for ext in exts:
            if ext or w not in targets:
                targets.append(w + ext)

    catchall_hash = _detect_catchall(base, sess, timeout)

    found = []
    skipped_catchall = 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {}
        for t in targets:
            f = pool.submit(_test_path, base, t, sess, timeout, follow_redirects)
            futures[f] = t

        for f in as_completed(futures):
            r = f.result()
            if r:
                if catchall_hash is not None and r.get("body_hash"):
                    if int(r["body_hash"], 16) == catchall_hash:
                        skipped_catchall += 1
                        continue
                found.append(r)
                if len(found) >= max_results:
                    pool.shutdown(wait=False)
                    break

    found.sort(key=lambda x: (x["status"], x["path"]))
    interesting = [x for x in found if x["status"] in (200, 401, 403, 301, 302, 500)]

    # body_hash 是内部去重用的, 从对外结果中移除
    for x in interesting:
        x.pop("body_hash", None)
    for x in found[:max_results]:
        x.pop("body_hash", None)

    return {
        "url": url,
        "total_tested": len(targets),
        "total_found": len(found),
        "interesting": interesting,
        "all": found[:max_results],
        "catchall_detected": catchall_hash is not None,
        "catchall_skipped": skipped_catchall,
    }
