import streamlit as st
import sqlite3
from scapy.all import sniff, IP, TCP, Raw
import pandas as pd
import threading
import binascii

# Set the page configuration as the first Streamlit command
st.set_page_config(layout="wide")  # Use the full screen width

# Initialize the SQLite database to store JA4L fingerprints
def init_db():
    conn = sqlite3.connect('fingerprints.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            ja4l_fingerprint TEXT,
            ja4l_a INTEGER,
            hop_count INTEGER,
            distance REAL
        )
    ''')
    conn.commit()
    conn.close()

# Calculate propagation delay factor based on hop count
def get_propagation_delay_factor(hop_count):
    if hop_count <= 21:
        return 1.5
    elif hop_count == 22:
        return 1.6
    elif hop_count == 23:
        return 1.7
    elif hop_count == 24:
        return 1.8
    elif hop_count == 25:
        return 1.9
    else:
        return 2.0

# Calculate estimated distance using the JA4L_a segment and hop count
def calculate_distance(ja4l_a, hop_count):
    c = 0.128  # Speed of light through fiber in m/us
    p = get_propagation_delay_factor(hop_count)
    distance = (ja4l_a * c) / p
    return round(distance, 2)

# Extract JA4L fingerprint information from raw TLS Client Hello
def extract_ja4l_fingerprint(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_data = packet[Raw].load
        # Debugging: Print raw data in hex
        print(f"Captured Raw Packet Data: {binascii.hexlify(raw_data)}")

        # Check if the packet starts with the TLS Client Hello pattern
        if raw_data[0] == 0x16 and raw_data[1] == 0x03:
            try:
                ja4l_a = int.from_bytes(raw_data[9:11], byteorder='big')  # Extract JA4L_a equivalent
                ja4l_fingerprint = f"Version: {ja4l_a}, Random: {raw_data[11:43].hex()}"  # Simplified fingerprint
                hop_count = packet[IP].ttl  # Use the TTL field as a rough approximation for hop count

                # Calculate the estimated distance
                distance = calculate_distance(ja4l_a, hop_count)

                # Save the extracted data to the database
                conn = sqlite3.connect('fingerprints.db')
                c = conn.cursor()
                c.execute('INSERT INTO fingerprints (ip, ja4l_fingerprint, ja4l_a, hop_count, distance) VALUES (?, ?, ?, ?, ?)',
                          (packet[IP].src, ja4l_fingerprint, ja4l_a, hop_count, distance))
                conn.commit()
                conn.close()
                print(f"Extracted Fingerprint: IP: {packet[IP].src}, JA4L_a: {ja4l_a}, Distance: {distance}")
            except Exception as e:
                print(f"Error parsing packet: {e}")

# Packet capturing function
def capture_packets():
    # Capture only TCP packets on port 443
    sniff(filter="tcp port 443", prn=extract_ja4l_fingerprint, store=False)  # Update iface if needed

# Function to display home page with estimated location
def display_home_page():
    st.title("JA4L Fingerprint Collector")
    st.markdown("This site records light distance/location fingerprints of your connection to study connection patterns.")
    
    # Display the latest estimated location data
    conn = sqlite3.connect('fingerprints.db')
    df = pd.read_sql_query("SELECT * FROM fingerprints ORDER BY id DESC LIMIT 1", conn)
    conn.close()

    if not df.empty:
        st.subheader("Estimated Location Data")
        # Display the dataframe without horizontal scrolling
        st.dataframe(df[['ip', 'ja4l_fingerprint', 'ja4l_a', 'hop_count', 'distance']], use_container_width=True)

        # Display fingerprint details and explanation
        st.subheader("Your Fingerprint Explained")
        ja4l_a = df['ja4l_a'].iloc[0]
        hop_count = df['hop_count'].iloc[0]
        distance = df['distance'].iloc[0]

        st.markdown(f"**JA4L_a (Version):** {ja4l_a} - Represents the TLS version, which is part of the Client Hello.")
        st.markdown(f"**Random Field:** A unique random value from the TLS handshake, part of the fingerprint.")
        st.markdown(f"**Hop Count (TTL):** {hop_count} - Indicates the number of network hops from your location to the server.")
        st.markdown(f"**Estimated Distance:** {distance} meters - Calculated using the JA4L_a and hop count, estimating how far you are from the server.")
    else:
        st.write("No data available yet.")

# Function to display analytics
def display_analytics_page():
    st.title("Analytics Dashboard")
    st.markdown("### Insights from Captured Fingerprints")

    conn = sqlite3.connect('fingerprints.db')
    df = pd.read_sql_query("SELECT * FROM fingerprints", conn)
    conn.close()

    if not df.empty:
        # Display basic statistics
        st.subheader("Basic Statistics")
        st.write(df.describe())

        # Show the most common JA4L fingerprints
        st.subheader("Most Common Fingerprints")
        common_fingerprints = df['ja4l_fingerprint'].value_counts().head(5)
        st.bar_chart(common_fingerprints)

        # Average estimated distance
        st.subheader("Average Estimated Distance")
        avg_distance = df['distance'].mean()
        st.write(f"Average Distance: {avg_distance:.2f} meters")

        # Distribution of hop counts
        st.subheader("Hop Count Distribution")
        st.bar_chart(df['hop_count'].value_counts())
    else:
        st.write("No data available yet.")

# Main function to run the Streamlit app
def main():
    init_db()
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox("Go to", ["Home", "Analytics"])

    if page == "Home":
        display_home_page()
    elif page == "Analytics":
        display_analytics_page()

# Start packet capture in a separate thread to keep Streamlit responsive
capture_thread = threading.Thread(target=capture_packets, daemon=True)
capture_thread.start()

if __name__ == '__main__':
    main()
