from flask import Flask
import mysql.connector
import os

app = Flask(__name__)

@app.route("/")
def home():

    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST","mysql"),
        user=os.getenv("DB_USER","admin"),
        password=os.getenv("DB_PASSWORD","password"),
        database=os.getenv("DB_NAME","demo")
    )

    cursor = conn.cursor()
    cursor.execute("SELECT message FROM greetings LIMIT 1")
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return f"""
    <h1>3 Tier Docker Compose Demo with frontend --> backend --> db</h1>
    <h2>{result[0]}</h2>
    """

app.run(host="0.0.0.0", port=5000)
