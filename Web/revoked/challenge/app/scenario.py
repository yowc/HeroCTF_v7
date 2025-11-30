import secrets
import sqlite3
import string
import time

import bcrypt
import requests

time.sleep(3)
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Add employees
employees = [
    ("Alice Johnson", "alice@example.com", "Software Engineer", "555-0101", "Office"),
    ("Bob Smith", "bob@example.com", "Data Scientist", "555-0102", "Remote"),
    ("Charlie Davis", "charlie@example.com", "Product Manager", "555-0103", "Office"),
    ("Diana Prince", "diana@example.com", "HR Manager", "555-0104", "Remote"),
    ("Eve Adams", "eve@example.com", "Security Analyst", "555-0105", "Office"),
    ("Frank Miller", "frank@example.com", "Marketing Manager", "555-0106", "Remote"),
    ("Grace Hopper", "grace@example.com", "Systems Architect", "555-0107", "Office"),
    ("Hank Pym", "hank@example.com", "Research Scientist", "555-0108", "Remote"),
    ("Ivy Carter", "ivy@example.com", "Sales Executive", "555-0109", "Office"),
    ("Jack Black", "jack@example.com", "Technical Writer", "555-0110", "Remote"),
    ("Kevin Hart", "kevin@example.com", "Business Analyst", "555-0111", "Office"),
    ("Lana Del Rey", "lana@example.com", "UX Designer", "555-0112", "Remote"),
    ("Michael Jordan", "michael@example.com", "DevOps Engineer", "555-0113", "Office"),
    ("Nancy Drew", "nancy@example.com", "AI Specialist", "555-0114", "Remote"),
    ("Oscar Wilde", "oscar@example.com", "Cloud Engineer", "555-0115", "Office"),
    ("Paula Abdul", "paula@example.com", "Finance Manager", "555-0116", "Remote"),
    ("Quincy Jones", "quincy@example.com", "Operations Manager", "555-0117", "Office"),
    ("Rachel Green", "rachel@example.com", "Legal Advisor", "555-0118", "Remote"),
    (
        "Steve Rogers",
        "steve@example.com",
        "Network Administrator",
        "555-0119",
        "Office",
    ),
    ("Tony Stark", "tony@example.com", "Customer Support Lead", "555-0120", "Remote"),
    ("Uma Thurman", "uma@example.com", "Scrum Master", "555-0121", "Office"),
    (
        "Victor Hugo",
        "victor@example.com",
        "Quality Assurance Engineer",
        "555-0122",
        "Remote",
    ),
    (
        "Wendy Darling",
        "wendy@example.com",
        "IT Support Specialist",
        "555-0123",
        "Office",
    ),
    (
        "Xander Cage",
        "xander@example.com",
        "Cybersecurity Engineer",
        "555-0124",
        "Remote",
    ),
    ("Yasmine Bleeth", "yasmine@example.com", "SEO Specialist", "555-0125", "Office"),
    ("Zack Morris", "zack@example.com", "Software Engineer", "555-0126", "Remote"),
    ("Amelia Earhart", "amelia@example.com", "Data Scientist", "555-0127", "Office"),
    ("Bruce Wayne", "bruce@example.com", "Product Manager", "555-0128", "Remote"),
    ("Clark Kent", "clark@example.com", "HR Manager", "555-0129", "Office"),
    ("Donna Noble", "donna@example.com", "Security Analyst", "555-0130", "Remote"),
    ("Elon Musk", "elon@example.com", "Marketing Manager", "555-0131", "Office"),
    ("Fiona Gallagher", "fiona@example.com", "Systems Architect", "555-0132", "Remote"),
    ("George Orwell", "george@example.com", "Research Scientist", "555-0133", "Office"),
    ("Harper Lee", "harper@example.com", "Sales Executive", "555-0134", "Remote"),
    ("Isaac Newton", "isaac@example.com", "Technical Writer", "555-0135", "Office"),
    (
        "Jennifer Lopez",
        "jennifer@example.com",
        "Business Analyst",
        "555-0136",
        "Remote",
    ),
    ("Kurt Cobain", "kurt@example.com", "UX Designer", "555-0137", "Office"),
    (
        "Leonardo Da Vinci",
        "leonardo@example.com",
        "DevOps Engineer",
        "555-0138",
        "Remote",
    ),
    ("Mila Kunis", "mila@example.com", "AI Specialist", "555-0139", "Office"),
    ("Noah Centineo", "noah@example.com", "Cloud Engineer", "555-0140", "Remote"),
    ("Oprah Winfrey", "oprah@example.com", "Finance Manager", "555-0141", "Office"),
    (
        "Patrick Stewart",
        "patrick@example.com",
        "Operations Manager",
        "555-0142",
        "Remote",
    ),
    ("Quentin Tarantino", "quentin@example.com", "Legal Advisor", "555-0143", "Office"),
    (
        "Robert Downey Jr.",
        "robert@example.com",
        "Network Administrator",
        "555-0144",
        "Remote",
    ),
    (
        "Scarlett Johansson",
        "scarlett@example.com",
        "Customer Support Lead",
        "555-0145",
        "Office",
    ),
    ("Tom Hanks", "tom@example.com", "Scrum Master", "555-0146", "Remote"),
    (
        "Uma Thurman",
        "uma@example.com",
        "Quality Assurance Engineer",
        "555-0147",
        "Office",
    ),
    ("Vin Diesel", "vin@example.com", "IT Support Specialist", "555-0148", "Remote"),
]

cursor.executemany(
    "INSERT OR IGNORE INTO employees (name, email, position, phone, location) VALUES (?, ?, ?, ?, ?)",
    employees,
)

password_admin = "pass"
password_hash = bcrypt.hashpw(password_admin.encode("utf-8"), bcrypt.gensalt()).decode(
    "utf-8"
)
cursor.execute(
    "INSERT INTO users (username, is_admin, password_hash) VALUES (?, ?, ?)",
    ("admin1", True, password_hash),
)

# Add admin user
password_admin = "".join([secrets.choice(string.hexdigits) for _ in range(32)])
password_hash = bcrypt.hashpw(password_admin.encode("utf-8"), bcrypt.gensalt()).decode(
    "utf-8"
)
cursor.execute(
    "INSERT INTO users (username, is_admin, password_hash) VALUES (?, ?, ?)",
    ("admin", True, password_hash),
)

# Add other user
password_user = "".join([secrets.choice(string.hexdigits) for _ in range(32)])
password_hash = bcrypt.hashpw(password_user.encode("utf-8"), bcrypt.gensalt()).decode(
    "utf-8"
)
cursor.execute(
    "INSERT INTO users (username, is_admin, password_hash) VALUES (?, ?, ?)",
    ("james", False, password_hash),
)

conn.commit()
conn.close()

# Log in and out to generate revoked token entry
s = requests.session()
s.post(
    "http://127.0.0.1:5000/login", data={"username": "james", "password": password_user}
)
s.get("http://127.0.0.1:5000/logout")

s = requests.session()
s.post(
    "http://127.0.0.1:5000/login",
    data={"username": "admin", "password": password_admin},
)
s.get("http://127.0.0.1:5000/logout")

s = requests.session()
s.post(
    "http://127.0.0.1:5000/login", data={"username": "james", "password": password_user}
)
s.get("http://127.0.0.1:5000/logout")
