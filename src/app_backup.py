import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import time
import json
import sqlite3
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
import uuid

# Configure page
st.set_page_config(
    page_title="DeepGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1e3a8a;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .threat-level-high {
        background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
    }
    .threat-level-medium {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
    }
    .threat-level-low {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #2C3E50 0%, #34495E 100%);
    }
</style>
""", unsafe_allow_html=True)

class DeepGuardAI:
    def __init__(self):
        self.setup_database()
        self.initialize_session_state()
    
    def setup_database(self):
        """Initialize SQLite database for storing threat data"""
        self.db_path = Path("data/deepguard.db")
        self.db_path.parent.mkdir(exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                timestamp DATETIME,
                threat_type TEXT,
                severity TEXT,
                risk_score REAL,
                source_ip TEXT,
                target_ip TEXT,
                description TEXT,
                status TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_traffic (
                id TEXT PRIMARY KEY,
                timestamp DATETIME,
                source_ip TEXT,
                dest_ip TEXT,
                port INTEGER,
                protocol TEXT,
                bytes_transferred INTEGER,
                packets INTEGER,
                is_anomalous BOOLEAN,
                anomaly_score REAL
            )
        """)
        
        conn.commit()
        conn.close()
    
    def initialize_session_state(self):
        """Initialize Streamlit session state variables"""
        if 'threats_detected' not in st.session_state:
            st.session_state.threats_detected = 0
        if 'risk_level' not in st.session_state:
            st.session_state.risk_level = "LOW"
        if 'last_update' not in st.session_state:
            st.session_state.last_update = datetime.now()
    
    def generate_sample_threat_data(self) -> pd.DataFrame:
        """Generate sample threat data for demonstration"""
        np.random.seed(int(time.time()) % 1000)
        
        threat_types = ['Malware', 'DDoS', 'Port Scan', 'Brute Force', 'Data Exfiltration', 'Insider Threat']
        severities = ['HIGH', 'MEDIUM', 'LOW']
        statuses = ['Active', 'Mitigated', 'Investigating']
        
        data = []
        for i in range(50):
            threat_type = np.random.choice(threat_types)
            severity = np.random.choice(severities, p=[0.2, 0.5, 0.3])
            
            data.append({
                'id': str(uuid.uuid4())[:8],
                'timestamp': datetime.now() - timedelta(hours=np.random.randint(0, 24)),
                'threat_type': threat_type,
                'severity': severity,
                'risk_score': np.random.uniform(0.1, 1.0),
                'source_ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'target_ip': f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'status': np.random.choice(statuses)
            })
        
        return pd.DataFrame(data)
    
    def generate_network_metrics(self) -> Dict:
        """Generate real-time network metrics"""
        return {
            'total_connections': np.random.randint(1000, 5000),
            'suspicious_activities': np.random.randint(5, 50),
            'blocked_attempts': np.random.randint(10, 100),
            'bandwidth_usage': np.random.uniform(60, 95),
            'threat_level': np.random.choice(['LOW', 'MEDIUM', 'HIGH'], p=[0.6, 0.3, 0.1])
        }
    
    def create_threat_timeline(self, df: pd.DataFrame) -> go.Figure:
        """Create threat timeline visualization"""
        fig = px.scatter(df, 
                        x='timestamp', 
                        y='risk_score',
                        color='severity',
                        size='risk_score',
                        hover_data=['threat_type', 'source_ip'],
                        title="Threat Timeline - Risk Score Over Time",
                        color_discrete_map={
                            'HIGH': '#ff4b2b',
                            'MEDIUM': '#f5576c',
                            'LOW': '#00f2fe'
                        })
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white'
        )
        
        return fig
    
    def create_threat_distribution(self, df: pd.DataFrame) -> go.Figure:
        """Create threat type distribution chart"""
        threat_counts = df['threat_type'].value_counts()
        
        fig = px.pie(values=threat_counts.values, 
                    names=threat_counts.index,
                    title="Threat Distribution by Type",
                    color_discrete_sequence=px.colors.sequential.Plasma_r)
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white'
        )
        
        return fig
    
    def create_risk_heatmap(self) -> go.Figure:
        """Create network risk heatmap"""
        # Generate sample IP ranges and risk scores
        ips = [f"192.168.{i}.{j}" for i in range(1, 11) for j in range(1, 11)]
        risk_scores = np.random.uniform(0, 1, len(ips))
        
        # Reshape for heatmap
        risk_matrix = risk_scores.reshape(10, 10)
        
        fig = go.Figure(data=go.Heatmap(
            z=risk_matrix,
            colorscale='Reds',
            showscale=True,
            colorbar=dict(title="Risk Score")
        ))
        
        fig.update_layout(
            title="Network Risk Heatmap",
            xaxis_title="IP Range (Last Octet)",
            yaxis_title="IP Range (Third Octet)",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white'
        )
        
        return fig
    
    def display_real_time_metrics(self, metrics: Dict):
        """Display real-time security metrics"""
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class="metric-container">
                <h3>🔗 Active Connections</h3>
                <h2>{metrics['total_connections']:,}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-container">
                <h3>⚠️ Suspicious Activities</h3>
                <h2>{metrics['suspicious_activities']}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="metric-container">
                <h3>🛡️ Blocked Attempts</h3>
                <h2>{metrics['blocked_attempts']}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            threat_class = f"threat-level-{metrics['threat_level'].lower()}"
            st.markdown(f"""
            <div class="{threat_class}">
                <h3>🚨 Threat Level</h3>
                <h2>{metrics['threat_level']}</h2>
            </div>
            """, unsafe_allow_html=True)
    
    def run(self):
        """Main application runner"""
        # Header
        st.markdown('<h1 class="main-header">🛡️ DeepGuard AI</h1>', unsafe_allow_html=True)
        st.markdown('<p style="text-align: center; font-size: 1.2rem; color: #64748b;">Real-Time Cybersecurity Risk Engine</p>', unsafe_allow_html=True)
        
        # Sidebar
        st.sidebar.header("🔧 Control Panel")
        
        # Auto-refresh toggle
        auto_refresh = st.sidebar.checkbox("🔄 Auto Refresh (5s)", value=True)
        
        # Threat sensitivity
        sensitivity = st.sidebar.slider("🎯 Detection Sensitivity", 0.1, 1.0, 0.7, 0.1)
        
        # Analysis mode
        analysis_mode = st.sidebar.selectbox(
            "📊 Analysis Mode",
            ["Real-Time Monitoring", "Historical Analysis", "Threat Hunting", "Risk Assessment"]
        )
        
        # Generate or refresh data
        if auto_refresh:
            time.sleep(0.1)  # Small delay for demo
        
        # Get current metrics and threat data
        metrics = self.generate_network_metrics()
        threat_df = self.generate_sample_threat_data()
        
        # Display real-time metrics
        self.display_real_time_metrics(metrics)
        
        # Main content area
        tab1, tab2, tab3, tab4 = st.tabs(["🎯 Live Threats", "📊 Analytics", "🗺️ Network Map", "🤖 AI Assistant"])
        
        with tab1:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("🎯 Active Threat Detection")
                
                # Filter threats
                severity_filter = st.multiselect(
                    "Filter by Severity:",
                    ['HIGH', 'MEDIUM', 'LOW'],
                    default=['HIGH', 'MEDIUM', 'LOW']
                )
                
                filtered_df = threat_df[threat_df['severity'].isin(severity_filter)]
                
                # Display threat table
                st.dataframe(
                    filtered_df[['timestamp', 'threat_type', 'severity', 'risk_score', 'source_ip', 'status']],
                    use_container_width=True
                )
            
            with col2:
                st.subheader("🚨 Recent Alerts")
                
                # Show recent high-risk threats
                high_risk_threats = threat_df[threat_df['severity'] == 'HIGH'].head(5)
                
                for _, threat in high_risk_threats.iterrows():
                    with st.container():
                        st.markdown(f"""
                        <div style="border-left: 4px solid #ff4b2b; padding-left: 1rem; margin: 1rem 0;">
                            <strong>{threat['threat_type']}</strong><br>
                            <small>Risk: {threat['risk_score']:.2f} | IP: {threat['source_ip']}</small>
                        </div>
                        """, unsafe_allow_html=True)
        
        with tab2:
            col1, col2 = st.columns(2)
            
            with col1:
                # Threat timeline
                timeline_fig = self.create_threat_timeline(threat_df)
                st.plotly_chart(timeline_fig, use_container_width=True)
            
            with col2:
                # Threat distribution
                distribution_fig = self.create_threat_distribution(threat_df)
                st.plotly_chart(distribution_fig, use_container_width=True)
            
            # Risk heatmap
            st.subheader("🗺️ Network Risk Heatmap")
            heatmap_fig = self.create_risk_heatmap()
            st.plotly_chart(heatmap_fig, use_container_width=True)
        
        with tab3:
            st.subheader("🗺️ Network Topology & Risk Mapping")
            st.info("Network mapping visualization will be implemented here")
            
            # Placeholder for network map
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Network Nodes", "127", "5")
            with col2:
                st.metric("Critical Assets", "23", "-2")
            with col3:
                st.metric("Risk Score", "0.73", "0.05")
        
        with tab4:
            st.subheader("🤖 DeepGuard AI Assistant")
            
            # Chat interface placeholder
            if 'chat_history' not in st.session_state:
                st.session_state.chat_history = []
            
            user_input = st.text_input("Ask me about security threats:", placeholder="What are the current high-risk threats?")
            
            if user_input:
                # Simple response logic (will be enhanced with actual AI)
                response = f"Based on current analysis, I detected {len(threat_df[threat_df['severity'] == 'HIGH'])} high-risk threats. The main concern is {threat_df['threat_type'].mode()[0]} attacks."
                
                st.session_state.chat_history.append({"user": user_input, "ai": response})
            
            # Display chat history
            for chat in st.session_state.chat_history[-5:]:  # Show last 5 exchanges
                st.write(f"**You:** {chat['user']}")
                st.write(f"**DeepGuard AI:** {chat['ai']}")
                st.write("---")
        
        # Auto-refresh mechanism
        if auto_refresh:
            time.sleep(5)
            st.rerun()

# Run the application
# Run the application
if __name__ == "__main__":
    app = DeepGuardAI()
    app.run()
