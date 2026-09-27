"""Check migration, volume persistence and online backup without provider calls."""
import pathlib
import subprocess
import time
import uuid


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def wait_for(probe, description):
    for _ in range(40):
        if probe():
            return
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {description}")


def main():
    suffix = uuid.uuid4().hex[:12]
    api, volume = f"asystant-check-{suffix}", f"asystant-data-check-{suffix}"
    env = {}
    for line in (pathlib.Path(__file__).resolve().parents[1] / ".env.example").read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            env[key] = value.strip("'")
    # Managed issuance stays disabled: the check never reaches OpenRouter.
    env_args = [part for key, value in env.items() for part in ("-e", f"{key}={value}")]

    def status(path):
        return run("docker", "exec", api, "curl", "--max-time", "4", "-s", "-o", "/dev/null",
                   "-w", "%{http_code}", f"http://127.0.0.1:8787/health/{path}", check=False).stdout

    def start(*mode):
        run("docker", "run", "-d", "--name", api, "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "-v", f"{volume}:/data",
            *env_args, "asystant-api:local", *mode)
        wait_for(lambda: status("live") == "200", "liveness")

    try:
        run("docker", "volume", "create", volume)
        start("--serve")
        assert status("ready") == "503", "Unmigrated schema must fail readiness"
        run("docker", "rm", "-f", api)
        start()
        wait_for(lambda: status("ready") == "200", "automatic migration")
        assert run("docker", "exec", api, "id", "-u").stdout.strip() == "10001"
        assert run("docker", "exec", api, "sqlite3", "/data/asystant.db", "PRAGMA journal_mode;").stdout.strip() == "wal"
        run("docker", "exec", api, "sqlite3", "/data/asystant.db",
            "INSERT INTO managed_clients (id, slug, name, key_hash, allowed_models, created_at) "
            f"VALUES ('persistence-test', 'persistence-test', 'Persistence', '{'a' * 64}', '[]', "
            "'2026-01-01 00:00:00+00:00');")
        run("docker", "exec", api, "sqlite3", "/data/asystant.db", ".backup /data/backup.db")
        run("docker", "rm", "-f", api)
        start()
        wait_for(lambda: status("ready") == "200", "restart readiness")
        for database in ("asystant.db", "backup.db"):
            assert run("docker", "exec", api, "sqlite3", f"/data/{database}",
                       "SELECT slug FROM managed_clients WHERE id = 'persistence-test';").stdout.strip() == "persistence-test"
            assert run("docker", "exec", api, "sqlite3", f"/data/{database}",
                       "PRAGMA integrity_check;").stdout.strip() == "ok"
        print("PASS: non-root read-only runtime, SQLite migration, restart persistence and online backup")
    finally:
        run("docker", "rm", "-f", api, check=False)
        run("docker", "volume", "rm", volume, check=False)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"Container check failed with exit code {error.returncode}") from None
