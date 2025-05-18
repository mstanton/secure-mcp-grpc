"""
Traffic Visualization for MCP-gRPC

This module provides creative visual representations of traffic patterns,
model interactions, and security events in the MCP-gRPC system.

It includes both real-time and historical visualizations designed to make
complex interaction patterns immediately understandable.

Author: Matthew Stanton && Claude.Ai
License: Apache 2.0
"""

import os
import json
import time
import datetime
import logging
from typing import Dict, List, Tuple, Any, Optional, Set, Union
import asyncio
from collections import defaultdict, Counter

# Data processing and manipulation
import pandas as pd
import numpy as np
from scipy import stats

# Visualization libraries
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
from wordcloud import WordCloud
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import seaborn as sns

# Dashboard components
import dash
from dash import dcc, html
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State

# Import tracer for data access
from secure_mcp_grpc.telemetry.interaction_tracer import InteractionTracer

# Configure logging
logger = logging.getLogger(__name__)


class TrafficVisualizer:
    """
    Creates visual representations of MCP-gRPC traffic patterns and model interactions.
    
    This class provides methods to generate various types of visualizations:
    - Real-time traffic flow diagrams
    - Interactive model interaction networks
    - Security event heatmaps
    - Performance metric dashboards
    - Anomaly detection visualizations
    """
    
    def __init__(
        self,
        tracer: InteractionTracer,
        data_dir: Optional[str] = None,
        refresh_interval: int = 5,  # seconds
        lookback_period: int = 24,  # hours
        max_datapoints: int = 10000,
        color_scheme: str = "plasma"
    ):
        """
        Initialize the traffic visualizer.
        
        Args:
            tracer: The interaction tracer providing the data
            data_dir: Directory for storing visualization data
            refresh_interval: How often to refresh visualizations (seconds)
            lookback_period: Time period to analyze (hours)
            max_datapoints: Maximum number of data points to process
            color_scheme: Color scheme for visualizations
        """
        self.tracer = tracer
        self.data_dir = data_dir or os.path.join(os.getcwd(), "visualizations")
        self.refresh_interval = refresh_interval
        self.lookback_period = lookback_period
        self.max_datapoints = max_datapoints
        self.color_scheme = color_scheme
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialize visualization cache
        self.visualization_cache = {}
        self.last_update_time = {}
        
        # State for real-time monitoring
        self.real_time_data = {
            "timestamps": [],
            "request_counts": [],
            "error_counts": [],
            "latencies": [],
            "security_events": []
        }
        
        # Cache processed datasets
        self._processed_data = {}
        
        # Initialize color maps
        self._init_color_maps()
        
        logger.info(f"Traffic visualizer initialized with data directory: {self.data_dir}")
    
    def _init_color_maps(self):
        """Initialize color maps for various visualization types."""
        # Color map for different event types
        self.event_colors = {
            "request": "#3498db",  # Blue
            "response": "#2ecc71",  # Green
            "security": "#e74c3c",  # Red
            "external_call": "#9b59b6",  # Purple
            "data_access": "#f39c12"   # Orange
        }
        
        # Color map for security events
        self.security_colors = {
            "authentication": "#e74c3c",  # Red
            "authorization": "#c0392b",   # Dark Red
            "rate_limit": "#d35400",      # Orange
            "anomaly": "#7d3c98"          # Purple
        }
        
        # Performance gradient
        self.performance_colorscale = [
            [0.0, "#2ecc71"],      # Green (good)
            [0.5, "#f1c40f"],      # Yellow (medium)
            [1.0, "#e74c3c"]       # Red (poor)
        ]
    
    async def load_interaction_data(self, hours: int = None) -> pd.DataFrame:
        """
        Load interaction data from the tracer logs.
        
        Args:
            hours: Number of hours to look back (defaults to self.lookback_period)
            
        Returns:
            DataFrame containing interaction events
        """
        if hours is None:
            hours = self.lookback_period
        
        # Check if we have recently processed data
        cache_key = f"interaction_data_{hours}"
        if cache_key in self._processed_data:
            last_update, data = self._processed_data[cache_key]
            if time.time() - last_update < self.refresh_interval:
                return data
        
        # Calculate time range
        end_time = time.time()
        start_time = end_time - (hours * 3600)
        
        # Process trace files within the time range
        all_events = []
        
        # Determine which trace files to process based on date
        start_date = datetime.datetime.fromtimestamp(start_time).date()
        end_date = datetime.datetime.fromtimestamp(end_time).date()
        current_date = start_date
        
        while current_date <= end_date:
            date_str = current_date.strftime("%Y-%m-%d")
            filename = f"interactions_{date_str}.jsonl"
            filepath = os.path.join(self.tracer.storage_path, filename)
            
            if os.path.exists(filepath):
                # Read the file in chunks to handle large files
                chunk_size = 10000  # Adjust based on memory constraints
                chunks = pd.read_json(filepath, lines=True, chunksize=chunk_size)
                
                for chunk in chunks:
                    # Filter events within the time range
                    mask = (chunk['timestamp'] >= start_time) & (chunk['timestamp'] <= end_time)
                    filtered_chunk = chunk[mask]
                    
                    # Append to events list
                    all_events.append(filtered_chunk)
                    
                    # Check if we've exceeded the maximum number of data points
                    if sum(len(df) for df in all_events) >= self.max_datapoints:
                        break
            
            # Move to the next day
            current_date += datetime.timedelta(days=1)
            
            # Check if we've exceeded the maximum number of data points
            if sum(len(df) for df in all_events) >= self.max_datapoints:
                break
        
        # Combine all chunks into a single DataFrame
        if not all_events:
            # Return empty DataFrame with expected columns
            df = pd.DataFrame(columns=[
                'id', 'timestamp', 'event_type', 'session_id', 
                'trace_id', 'span_id', 'parent_span_id', 'timestamp_iso'
            ])
        else:
            df = pd.concat(all_events, ignore_index=True)
        
        # Cache the processed data
        self._processed_data[cache_key] = (time.time(), df)
        
        return df
    
    async def generate_traffic_flow_diagram(self, hours: int = None) -> Dict[str, Any]:
        """
        Generate a traffic flow diagram showing the flow of requests through the system.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with the figure data and metadata
        """
        cache_key = f"traffic_flow_{hours or self.lookback_period}"
        
        # Check if we have a cached version
        if cache_key in self.visualization_cache:
            last_update, vis_data = self.visualization_cache[cache_key]
            if time.time() - last_update < self.refresh_interval:
                return vis_data
        
        # Load interaction data
        df = await self.load_interaction_data(hours)
        
        # Prepare nodes and links for the Sankey diagram
        if len(df) == 0:
            # Return empty diagram if no data
            fig = go.Figure(go.Sankey(
                node=dict(
                    label=["No Data"],
                    color=["#cccccc"]
                ),
                link=dict(
                    source=[],
                    target=[],
                    value=[]
                )
            ))
            
            fig.update_layout(
                title_text="Traffic Flow (No Data Available)",
                font_size=12
            )
            
            result = {
                "figure": fig.to_json(),
                "timestamp": time.time(),
                "datapoints": 0
            }
            
            self.visualization_cache[cache_key] = (time.time(), result)
            return result
        
        # Extract external call events to build the flow diagram
        external_calls = df[df['event_type'] == 'external_call']
        
        # If we don't have external calls, use session to method mapping
        if len(external_calls) == 0:
            # Use request events to build a simplified flow
            requests = df[df['event_type'] == 'request']
            
            if len(requests) == 0:
                # Return empty diagram if no data
                fig = go.Figure(go.Sankey(
                    node=dict(
                        label=["No Request Data"],
                        color=["#cccccc"]
                    ),
                    link=dict(
                        source=[],
                        target=[],
                        value=[]
                    )
                ))
                
                fig.update_layout(
                    title_text="Traffic Flow (No Request Data Available)",
                    font_size=12
                )
                
                result = {
                    "figure": fig.to_json(),
                    "timestamp": time.time(),
                    "datapoints": 0
                }
                
                self.visualization_cache[cache_key] = (time.time(), result)
                return result
            
            # Group requests by session and method
            flow_data = requests.groupby(['session_id', 'method']).size().reset_index(name='count')
            
            # Create nodes for sessions and methods
            all_sessions = flow_data['session_id'].unique()
            all_methods = flow_data['method'].unique()
            
            # Create node lists
            node_labels = list(all_sessions) + list(all_methods)
            
            # Map sessions and methods to node indices
            session_to_idx = {session: i for i, session in enumerate(all_sessions)}
            method_to_idx = {method: i + len(all_sessions) for i, method in enumerate(all_methods)}
            
            # Create links
            sources = []
            targets = []
            values = []
            
            for _, row in flow_data.iterrows():
                sources.append(session_to_idx[row['session_id']])
                targets.append(method_to_idx[row['method']])
                values.append(row['count'])
            
            # Create color map
            node_colors = ["#3498db"] * len(all_sessions) + ["#2ecc71"] * len(all_methods)
            
            # Create Sankey diagram
            fig = go.Figure(go.Sankey(
                node=dict(
                    label=node_labels,
                    color=node_colors,
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5)
                ),
                link=dict(
                    source=sources,
                    target=targets,
                    value=values,
                    color=["rgba(52, 152, 219, 0.4)"] * len(sources)  # Slightly transparent blue
                )
            ))
        else:
            # Use external call events to build a more detailed flow
            # Group by source session, target system, and target method
            flow_data = external_calls.groupby(
                ['session_id', 'target_system', 'target_method']
            ).size().reset_index(name='count')
            
            # Create nodes for sessions, systems, and methods
            all_sessions = flow_data['session_id'].unique()
            all_systems = flow_data['target_system'].unique()
            
            # Create combined system:method nodes
            system_methods = flow_data.apply(
                lambda row: f"{row['target_system']}:{row['target_method']}", axis=1
            ).unique()
            
            # Create node lists
            node_labels = list(all_sessions) + list(all_systems) + list(system_methods)
            
            # Map to node indices
            session_to_idx = {session: i for i, session in enumerate(all_sessions)}
            system_to_idx = {system: i + len(all_sessions) for i, system in enumerate(all_systems)}
            system_method_to_idx = {
                sm: i + len(all_sessions) + len(all_systems) 
                for i, sm in enumerate(system_methods)
            }
            
            # Create links
            sources = []
            targets = []
            values = []
            
            # First set of links: session -> system
            session_system_flow = flow_data.groupby(['session_id', 'target_system'])['count'].sum().reset_index()
            
            for _, row in session_system_flow.iterrows():
                sources.append(session_to_idx[row['session_id']])
                targets.append(system_to_idx[row['target_system']])
                values.append(row['count'])
            
            # Second set of links: system -> system:method
            for _, row in flow_data.iterrows():
                system_method = f"{row['target_system']}:{row['target_method']}"
                sources.append(system_to_idx[row['target_system']])
                targets.append(system_method_to_idx[system_method])
                values.append(row['count'])
            
            # Create color map
            node_colors = (
                ["#3498db"] * len(all_sessions) +      # Sessions: Blue
                ["#9b59b6"] * len(all_systems) +       # Systems: Purple
                ["#2ecc71"] * len(system_methods)      # Methods: Green
            )
            
            # Create Sankey diagram
            fig = go.Figure(go.Sankey(
                node=dict(
                    label=node_labels,
                    color=node_colors,
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5)
                ),
                link=dict(
                    source=sources,
                    target=targets,
                    value=values,
                    color=[
                        "rgba(52, 152, 219, 0.4)" if i < len(session_system_flow) else "rgba(155, 89, 182, 0.4)"
                        for i in range(len(sources))
                    ]
                )
            ))
        
        # Update layout
        time_range_str = f"Last {hours or self.lookback_period} hours"
        fig.update_layout(
            title_text=f"MCP Traffic Flow ({time_range_str})",
            font_size=12,
            autosize=True,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        # Return the figure as JSON
        result = {
            "figure": fig.to_json(),
            "timestamp": time.time(),
            "datapoints": len(df)
        }
        
        # Cache the result
        self.visualization_cache[cache_key] = (time.time(), result)
        
        return result
    
    async def generate_interaction_network(self, hours: int = None) -> Dict[str, Any]:
        """
        Generate an interactive network visualization of model interactions.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with the figure data and metadata
        """
        cache_key = f"interaction_network_{hours or self.lookback_period}"
        
        # Check if we have a cached version
        if cache_key in self.visualization_cache:
            last_update, vis_data = self.visualization_cache[cache_key]
            if time.time() - last_update < self.refresh_interval:
                return vis_data
        
        # Get the model interaction graph from the tracer
        interaction_graph = self.tracer.get_model_interaction_graph()
        
        if not interaction_graph:
            # Create empty network diagram
            fig = go.Figure(go.Scatter(
                x=[0],
                y=[0],
                mode='markers',
                marker=dict(size=20, color='#cccccc'),
                text=['No Data'],
                hoverinfo='text'
            ))
            
            fig.update_layout(
                title_text="Model Interaction Network (No Data Available)",
                showlegend=False,
                autosize=True,
                margin=dict(l=20, r=20, t=40, b=20),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
            
            result = {
                "figure": fig.to_json(),
                "timestamp": time.time(),
                "datapoints": 0
            }
            
            self.visualization_cache[cache_key] = (time.time(), result)
            return result
        
        # Create a NetworkX graph
        G = nx.DiGraph()
        
        # Add nodes and edges
        for source, targets in interaction_graph.items():
            # Ensure the source node exists
            if source not in G:
                G.add_node(source)
            
            # Add edges to all targets
            for target in targets:
                if target not in G:
                    G.add_node(target)
                G.add_edge(source, target)
        
        # Calculate node positions using a spring layout
        pos = nx.spring_layout(G, seed=42)
        
        # Prepare node data
        node_x = []
        node_y = []
        node_text = []
        node_size = []
        node_color = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
            
            # Node size based on degree
            size = 10 + (G.degree(node) * 5)
            node_size.append(size)
            
            # Color based on node type
            if ":" in node:  # External system node
                node_color.append('#9b59b6')  # Purple
            else:  # Session node
                node_color.append('#3498db')  # Blue
        
        # Prepare edge data
        edge_x = []
        edge_y = []
        edge_text = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            
            # Add line with a Bezier curve
            edge_x.append(x0)
            edge_x.append((x0 + x1) / 2 + (y1 - y0) * 0.1)  # Control point for curve
            edge_x.append(x1)
            edge_x.append(None)  # Break the line
            
            edge_y.append(y0)
            edge_y.append((y0 + y1) / 2 + (x0 - x1) * 0.1)  # Control point for curve
            edge_y.append(y1)
            edge_y.append(None)  # Break the line
            
            # Edge label
            edge_text.append(f"{edge[0]} → {edge[1]}")
            edge_text.append("")
            edge_text.append("")
            edge_text.append("")
        
        # Create edge trace
        edge_trace = go.Scatter(
            x=edge_x, 
            y=edge_y,
            line=dict(width=1, color='rgba(150,150,150,0.7)'),
            hoverinfo='text',
            text=edge_text,
            mode='lines'
        )
        
        # Create node trace
        node_trace = go.Scatter(
            x=node_x, 
            y=node_y,
            mode='markers',
            hoverinfo='text',
            text=node_text,
            marker=dict(
                color=node_color,
                size=node_size,
                line=dict(width=1, color='#333333')
            )
        )
        
        # Add arrow heads to edges
        arrow_trace = go.Scatter(
            x=[], 
            y=[],
            mode='markers',
            marker=dict(
                symbol='arrow',
                size=8,
                color='rgba(150,150,150,0.7)',
                angle=0
            ),
            hoverinfo='skip'
        )
        
        # Calculate arrow positions and angles
        arrow_x = []
        arrow_y = []
        arrow_angles = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            
            # Position the arrow near the target
            ratio = 0.85  # Position along the edge
            arrow_x.append(x0 + ratio * (x1 - x0))
            arrow_y.append(y0 + ratio * (y1 - y0))
            
            # Calculate angle
            angle = np.arctan2(y1 - y0, x1 - x0) * 180 / np.pi
            arrow_angles.append(angle)
        
        # Update arrow trace
        arrow_trace.x = arrow_x
        arrow_trace.y = arrow_y
        arrow_trace.marker.angle = arrow_angles
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace, arrow_trace])
        
        # Update layout
        time_range_str = f"Last {hours or self.lookback_period} hours"
        fig.update_layout(
            title_text=f"Model Interaction Network ({time_range_str})",
            showlegend=False,
            autosize=True,
            margin=dict(l=20, r=20, t=40, b=20),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        
        # Return the figure as JSON
        result = {
            "figure": fig.to_json(),
            "timestamp": time.time(),
            "datapoints": len(G.nodes())
        }
        
        # Cache the result
        self.visualization_cache[cache_key] = (time.time(), result)
        
        return result
    
    async def generate_security_heatmap(self, hours: int = None) -> Dict[str, Any]:
        """
        Generate a heatmap of security events.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with the figure data and metadata
        """
        cache_key = f"security_heatmap_{hours or self.lookback_period}"
        
        # Check if we have a cached version
        if cache_key in self.visualization_cache:
            last_update, vis_data = self.visualization_cache[cache_key]
            if time.time() - last_update < self.refresh_interval:
                return vis_data
        
        # Load interaction data
        df = await self.load_interaction_data(hours)
        
        # Filter security events
        security_events = df[df['event_type'] == 'security']
        
        if len(security_events) == 0:
            # Return empty heatmap if no data
            fig = go.Figure(go.Heatmap(
                z=[[0]],
                x=['No Data'],
                y=['No Data'],
                colorscale=[[0, '#f8f9fa'], [1, '#f8f9fa']],
                showscale=False
            ))
            
            fig.update_layout(
                title_text="Security Events Heatmap (No Data Available)",
                xaxis=dict(title="Time Period"),
                yaxis=dict(title="Security Event Type"),
                autosize=True,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            result = {
                "figure": fig.to_json(),
                "timestamp": time.time(),
                "datapoints": 0
            }
            
            self.visualization_cache[cache_key] = (time.time(), result)
            return result
        
        # Convert timestamp to datetime for easier binning
        security_events['datetime'] = pd.to_datetime(security_events['timestamp'], unit='s')
        
        # Define time bins based on the time range
        if hours <= 2:
            # Use 5-minute bins for short time ranges
            security_events['time_bin'] = security_events['datetime'].dt.floor('5min')
            time_bin_format = '%H:%M'
        elif hours <= 24:
            # Use 1-hour bins for medium time ranges
            security_events['time_bin'] = security_events['datetime'].dt.floor('H')
            time_bin_format = '%H:%M'
        else:
            # Use 6-hour bins for long time ranges
            security_events['time_bin'] = security_events['datetime'].dt.floor('6H')
            time_bin_format = '%m-%d %H:%M'
        
        # Count events by security type and time bin
        if 'security_type' in security_events.columns:
            # Group by security_type and time_bin
            heatmap_data = security_events.groupby(['security_type', 'time_bin']).size().reset_index(name='count')
            
            # Pivot the data for the heatmap
            pivot_data = heatmap_data.pivot_table(
                values='count', 
                index='security_type',
                columns='time_bin',
                fill_value=0
            )
        else:
            # If security_type is not available, use a generic 'security' type
            security_events['security_type'] = 'security'
            
            # Group by security_type and time_bin
            heatmap_data = security_events.groupby(['security_type', 'time_bin']).size().reset_index(name='count')
            
            # Pivot the data for the heatmap
            pivot_data = heatmap_data.pivot_table(
                values='count', 
                index='security_type',
                columns='time_bin',
                fill_value=0
            )
        
        # Format the time bin labels
        time_labels = [t.strftime(time_bin_format) for t in pivot_data.columns]
        
        # Create the heatmap
        fig = go.Figure(go.Heatmap(
            z=pivot_data.values,
            x=time_labels,
            y=pivot_data.index,
            colorscale='Viridis',
            showscale=True,
            colorbar=dict(title="Count")
        ))
        
        # Overlay text with counts
        fig.add_trace(go.Scatter(
            x=[item for item in time_labels for _ in range(len(pivot_data.index))],
            y=[item for _ in range(len(time_labels)) for item in pivot_data.index],
            text=pivot_data.values.flatten(),
            mode='text',
            textfont=dict(color='white'),
            showlegend=False
        ))
        
        # Update layout
        time_range_str = f"Last {hours or self.lookback_period} hours"
        fig.update_layout(
            title_text=f"Security Events Heatmap ({time_range_str})",
            xaxis=dict(title="Time Period"),
            yaxis=dict(title="Security Event Type"),
            autosize=True,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        # Return the figure as JSON
        result = {
            "figure": fig.to_json(),
            "timestamp": time.time(),
            "datapoints": len(security_events)
        }
        
        # Cache the result
        self.visualization_cache[cache_key] = (time.time(), result)
        
        return result
    
    async def generate_latency_distribution(self, hours: int = None) -> Dict[str, Any]:
        """
        Generate a visualization of latency distribution across different methods.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with the figure data and metadata
        """
        cache_key = f"latency_distribution_{hours or self.lookback_period}"
        
        # Check if we have a cached version
        if cache_key in self.visualization_cache:
            last_update, vis_data = self.visualization_cache[cache_key]
            if time.time() - last_update < self.refresh_interval:
                return vis_data
        
        # Load interaction data
        df = await self.load_interaction_data(hours)
        
        # Filter response events
        response_events = df[df['event_type'] == 'response']
        
        if len(response_events) == 0 or 'processing_time_ms' not in response_events.columns:
            # Return empty violin plot if no data
            fig = go.Figure()
            
            fig.update_layout(
                title_text="Latency Distribution (No Data Available)",
                xaxis=dict(title="Method"),
                yaxis=dict(title="Processing Time (ms)"),
                autosize=True,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            result = {
                "figure": fig.to_json(),
                "timestamp": time.time(),
                "datapoints": 0
            }
            
            self.visualization_cache[cache_key] = (time.time(), result)
            return result
        
        # Get the request events to match methods
        request_events = df[df['event_type'] == 'request']
        
        # Join response events with request events to get the method
        if 'request_id' in response_events.columns and 'id' in request_events.columns:
            # Create a mapping from request id to method
            request_id_to_method = dict(zip(request_events['id'], request_events['method']))
            
            # Add method to response events
            response_events['method'] = response_events['request_id'].map(request_id_to_method)
        
        # Remove responses without a method
        response_events = response_events.dropna(subset=['method'])
        
        # Get top methods by count
        method_counts = response_events['method'].value_counts()
        top_methods = method_counts.head(10).index.tolist()
        
        # Filter for top methods
        top_method_responses = response_events[response_events['method'].isin(top_methods)]
        
        # Create violin plots for latency distribution
        fig =