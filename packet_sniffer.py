from scapy.all import sniff, IP, TCP, Raw
import sqlite3
import binascii

# Initialize the SQLite database to ensure the table has the required columns
def init_db():
    conn = sqlite3.connect('fingerprints.db')
    c = conn.cursor()
    # Create the table if it does not exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            ja4l_fingerprint TEXT,
            ja4t_fingerprint TEXT,
            ja4_fingerprint TEXT,
            ja4l_a INTEGER,
            hop_count INTEGER,
            distance REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Update the database schema to add missing columns if the table already exists
def update_db_schema():
    conn = sqlite3.connect('fingerprints.db')
    c = conn.cursor()
    # Attempt to add each column if missing
    try:
        c.execute('ALTER TABLE fingerprints ADD COLUMN ja4t_fingerprint TEXT')
    except sqlite3.OperationalError:
        print("Column ja4t_fingerprint already exists.")
    
    try:
        c.execute('ALTER TABLE fingerprints ADD COLUMN ja4_fingerprint TEXT')
    except sqlite3.OperationalError:
        print("Column ja4_fingerprint already exists.")

    try:
        c.execute('ALTER TABLE fingerprints ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP')
    except sqlite3.OperationalError:
        print("Column timestamp already exists.")

    conn.commit()
    conn.close()

# Securely execute database queries
def execute_db(query, params=()):
    conn = sqlite3.connect('fingerprints.db')
    c = conn.cursor()
    c.execute(query, params)
    conn.commit()
    results = c.fetchall()
    conn.close()
    return results

# Calculate estimated distance based on JA4L_a segment and hop count
def calculate_distance(ja4l_a, hop_count):
    c = 0.128  # Speed of light through fiber in m/us
    p = 1.5 + 0.1 * max(0, hop_count - 21)
    return round((ja4l_a * c) / p, 2)

# Extract JA4L, JA4T, and JA4 fingerprints
def extract_fingerprints(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_data = packet[Raw].load
        if raw_data[0] == 0x16 and raw_data[1] == 0x03:  # Check for TLS Client Hello
            try:
                ja4l_a = int.from_bytes(raw_data[9:11], byteorder='big')
                ja4l_fingerprint = f"Version: {ja4l_a}, Random: {raw_data[11:43].hex()}"
                timestamp = int.from_bytes(raw_data[43:47], byteorder='big')
                ja4t_fingerprint = f"Timestamp: {timestamp}, Extensions: {binascii.hexlify(raw_data[47:60]).decode('utf-8')}"
                ja4_fingerprint = f"JA4 Combined: {ja4l_fingerprint}, {ja4t_fingerprint}"
                hop_count = packet[IP].ttl
                distance = calculate_distance(ja4l_a, hop_count)

                # Log the captured data for verification
                print(f"Captured packet from IP: {packet[IP].src} - JA4L_a: {ja4l_a} - Distance: {distance}")

                execute_db(
                    'INSERT INTO fingerprints (ip, ja4l_fingerprint, ja4t_fingerprint, ja4_fingerprint, ja4l_a, hop_count, distance) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (packet[IP].src, ja4l_fingerprint, ja4t_fingerprint, ja4_fingerprint, ja4l_a, hop_count, distance)
                )

            except Exception as e:
                print(f"Error parsing packet: {e}")

# Function to start packet sniffing
def start_sniffing():
    print("Starting packet sniffer on port 443...")
    # Start sniffing TLS packets on port 443
    sniff(filter="tcp port 443", prn=extract_fingerprints, store=False)

if __name__ == '__main__':
    init_db()
    update_db_schema()  # Ensure the schema is up-to-date
    start_sniffing()
