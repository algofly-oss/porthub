"""First start of the embedded MongoDB.

Creates the root user from MONGO_INITDB_ROOT_USERNAME/PASSWORD. If
/data/restore/mongo.archive.gz exists (a mongodump --archive --gzip of a
previous PortHub database) it is restored first; the old admin database is
skipped so only the new root credentials apply. Marks completion so this
runs once.
"""
import os
import subprocess
import sys
import time

from pymongo import MongoClient

DBPATH = "/data/mongo"
ARCHIVE = "/data/restore/mongo.archive.gz"
MARKER = os.path.join(DBPATH, ".porthub-initialized")

user = os.environ["MONGO_INITDB_ROOT_USERNAME"]
password = os.environ["MONGO_INITDB_ROOT_PASSWORD"]
mongod = subprocess.Popen(["mongod", "--bind_ip", "127.0.0.1", "--port", "47017", "--dbpath", DBPATH, "--quiet"],
                          stdout=subprocess.DEVNULL)
try:
    client = MongoClient("mongodb://127.0.0.1:47017", serverSelectionTimeoutMS=2000)
    for _ in range(60):
        try:
            client.admin.command("ping")
            break
        except Exception:
            time.sleep(1)
    else:
        sys.exit("mongod did not start")
    if os.path.exists(ARCHIVE):
        print("restoring", ARCHIVE, flush=True)
        for attempt in range(3):
            result = subprocess.run(["mongorestore", "--uri", "mongodb://127.0.0.1:47017", "--gzip", f"--archive={ARCHIVE}",
                                     "--nsExclude=admin.*", "--drop"], capture_output=True, text=True)
            if result.returncode == 0:
                print((result.stderr.strip().splitlines() or ["restored"])[-1], flush=True)
                break
            print("restore attempt failed:\n" + "\n".join(result.stderr.strip().splitlines()[-8:]), flush=True)
            time.sleep(3)
        else:
            sys.exit("could not restore the database archive")
    if client.admin.command("usersInfo", user)["users"]:
        client.admin.command("updateUser", user, pwd=password)
    else:
        client.admin.command("createUser", user, pwd=password, roles=["root"])
    open(MARKER, "w").close()
    print("database initialized", flush=True)
finally:
    try:
        MongoClient("mongodb://127.0.0.1:47017").admin.command("shutdown")
    except Exception:
        pass
    mongod.wait(timeout=60)
