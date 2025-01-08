import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import IP, TCP, UDP, ICMP, sniff
from collections import defaultdict, deque
import time
from datetime import datetime
import threading
import warnings
import logging
from typing import Dict, List, Optional
import socket
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.packet_data = deque(maxlen=10000)  # Use a deque to limit stored packets
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.filter = {'protocol': None, 'source': None, 'destination': None}

    def get_protocol_name(self, protocol_num: int) -> str:
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }

                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    # Apply filters
                    if (self.filter['protocol'] and packet_info['protocol'] != self.filter['protocol']) or \
                       (self.filter['source'] and packet_info['source'] != self.filter['source']) or \
                       (self.filter['destination'] and packet_info['destination'] != self.filter['destination']):
                        return

                    self.packet_data.append(packet_info)
                    self.packet_count += 1

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        with self.lock:
            return pd.DataFrame(self.packet_data)

    def set_filter(self, protocol: Optional[str], source: Optional[str], destination: Optional[str]):
        self.filter['protocol'] = protocol
        self.filter['source'] = source
        self.filter['destination'] = destination


def create_visualizations(df: pd.DataFrame):
    if len(df) > 0:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,
            title="Packets per Second"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)

        # Top destination IPs
        top_destinations = df['destination'].value_counts().head(10)
        fig_destinations = px.bar(
            x=top_destinations.index,
            y=top_destinations.values,
            title="Top Destination IP Addresses"
        )
        st.plotly_chart(fig_destinations, use_container_width=True)

        # Packet size distribution
        fig_size = px.histogram(
            df,
            x='size',
            title="Packet Size Distribution"
        )
        st.plotly_chart(fig_size, use_container_width=True)


def start_packet_capture(processor: PacketProcessor, interface: str):
    def capture_packets():
        sniff(prn=processor.process_packet, store=False, iface=interface)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

def main():
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # Initialize packet processor in session state
    if 'processor' not in st.session_state:
        st.session_state.processor = PacketProcessor()
        st.session_state.interface = 'eth0'  # Default interface
        st.session_state.capturing = False  # Default capturing state

    # Create dashboard layout
    col1, col2 = st.columns(2)

    # Get current data
    df = st.session_state.processor.get_dataframe()

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.processor.start_time.timestamp()
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )

    # Interface selection
    st.sidebar.title("Settings")
    st.session_state.interface = st.sidebar.selectbox(
        "Select Interface",
        ['eth0', 'wlan0', 'lo']
    )

    # Start/Stop capture
    if st.sidebar.button('Start Capture'):
        start_packet_capture(st.session_state.processor, st.session_state.interface)
        st.session_state.capturing = True
    elif st.sidebar.button('Stop Capture'):
        st.session_state.capturing = False

    # Filtering options
    st.sidebar.subheader("Filtering Options")
    protocol_filter = st.sidebar.selectbox(
        "Protocol",
        ['TCP', 'UDP', 'ICMP', 'None']
    )
    source_filter = st.sidebar.text_input("Source IP")
    destination_filter = st.sidebar.text_input("Destination IP")

    if protocol_filter != 'None':
        st.session_state.processor.set_filter(protocol_filter, source_filter, destination_filter)
    else:
        st.session_state.processor.set_filter(None, None, None)

    # Export options
    st.sidebar.subheader("Export Options")
    export_format = st.sidebar.selectbox(
        "Format",
        ['CSV', 'JSON']
    )

    if st.sidebar.button('Export Data'):
        if export_format == 'CSV':
            df.to_csv('packet_data.csv', index=False)
            st.success("Data exported to packet_data.csv")
        elif export_format == 'JSON':
            df.to_json('packet_data.json', orient='records')
            st.success("Data exported to packet_data.json")


if __name__ == "__main__":
    main()