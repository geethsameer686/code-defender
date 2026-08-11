"""Intentionally vulnerable payment module — Defender demo fixture.

DO NOT ship anything resembling this. Every line here is bait for a Defender
quality layer. Run: `defender scan examples/vulnerable_payment.py`
"""

import hashlib
import pickle
import random

import requests

# SEC-HARDCODED-SECRET + PCI: secrets in source
API_KEY = "sk_live_abcdef1234567890secret"
DB_PASSWORD = "SuperSecret123"

DEBUG = True  # SEC-DEBUG-ENABLED


def charge_card(card_number, cvv, amount):
    # PCI-PAN-VARIABLE + PCI-CVV-HANDLING: cardholder data in scope
    # GDPR-PII-LOGGING: logging sensitive data
    print("Charging card_number=" + card_number + " cvv=" + cvv)

    # VULN-INSECURE-RANDOM: not crypto-safe
    txn_id = random.randint(1000, 9999)

    # SEC-WEAK-HASH
    signature = hashlib.md5((card_number + str(amount)).encode()).hexdigest()

    # SEC-SQL-INJECTION
    query = f"INSERT INTO payments SELECT * FROM cards WHERE number = '{card_number}'"
    execute(query)

    # SEC-TLS-DISABLED + VULN-REQUESTS-NO-TIMEOUT + VULN-HTTP-URL
    resp = requests.post(
        "http://payments.example.com/charge", data={"n": card_number}, verify=False
    )
    return {"txn": txn_id, "sig": signature, "resp": resp}


def load_config(blob):
    # SEC-INSECURE-DESERIALIZE
    return pickle.loads(blob)


def run_rule(expr):
    # SEC-EVAL-EXEC
    return eval(expr)  # noqa


def process_all(cards):
    results = []
    for card in cards:
        # PERF-QUERY-IN-LOOP (N+1)
        row = db.execute("SELECT * FROM ledger WHERE id = %s" % card)  # PERF-SELECT-STAR
        results.append(row)
    return results
