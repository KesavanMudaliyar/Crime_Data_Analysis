# -----------------------------
# Python Script: upload_crimes_no_pandas.py
# -----------------------------

import csv
import pyodbc

# -----------------------------
# CONFIGURATION - UPDATE THIS
# -----------------------------
CSV_PATH = r"C:\Users\ACER\OneDrive\Documents\crime\CrimesOnWomenData.csv"  # <-- your CSV path
SQL_SERVER = r"localhost\SQLEXPRESS01"
DATABASE = "CrimesDB"
USERNAME = "myuser"
PASSWORD = "MyP@ssw0rd"

# -----------------------------
# CONNECT TO SQL SERVER
# -----------------------------
try:
    conn = pyodbc.connect(
    	f'DRIVER={{ODBC Driver 18 for SQL Server}};'  # must match exactly
        f'SERVER={SQL_SERVER};'
        f'DATABASE={DATABASE};'
        f'UID={USERNAME};'
        f'PWD={PASSWORD};'
        'TrustServerCertificate=yes;'
    )
    cursor = conn.cursor()
    print("✅ Connection to SQL Server successful!")
except Exception as e:
    print("❌ Connection failed:", e)
    exit(1)

# -----------------------------
# READ CSV AND INSERT INTO SQL
# -----------------------------
try:
    with open(CSV_PATH, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        rows_inserted = 0
        for row in reader:
            cursor.execute("""
                INSERT INTO Crimes (IncidentID, DateOccurred, State, District, CrimeType, VictimAge, Description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                int(row['IncidentID']),
                row['Date'],
                row['State'],
                row['District'],
                row['CrimeType'],
                int(row['VictimAge']) if row['VictimAge'] else None,
                row['Description'] if row['Description'] else None
            ))
            rows_inserted += 1

        conn.commit()
        print(f"✅ {rows_inserted} rows inserted successfully!")
except Exception as e:
    print("❌ Failed to read CSV or insert data:", e)
    exit(1)
finally:
    cursor.close()
    conn.close()

print("🎉 Data upload complete!")
