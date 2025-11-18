# src/bountybot/data/model.py

import sqlite3
import json
from datetime import datetime

DB_PATH = "arcanum_memory.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attack_success_log
                 (id INTEGER PRIMARY KEY,
                 timestamp TEXT,
                 chain_description TEXT,
                 result TEXT,
                 tags TEXT)''')
    conn.commit()
    conn.close()


def log_attack_result(chain_description, success, tags):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("INSERT INTO attack_success_log (timestamp, chain_description, result, tags) VALUES (?, ?, ?, ?)",
              (now, chain_description, success, json.dumps(tags)))
    conn.commit()
    conn.close()


def retrieve_successful_chains(threshold=70):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT chain_description, tags FROM attack_success_log WHERE result=?", ("success",))
    results = c.fetchall()
    conn.close()

    output = []
    for desc, tags_json in results:
        try:
            output.append((desc, json.loads(tags_json)))
        except json.JSONDecodeError:
            continue

    return output