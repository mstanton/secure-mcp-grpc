"""
Telemetry Dashboard for Secure MCP-gRPC

This module provides a web-based dashboard for visualizing telemetry data
collected from MCP-gRPC servers. It offers real-time monitoring of traffic
patterns, security events, and performance metrics.

Author: Matthew Stanton && Claude.Ai
License: Apache 2.0
"""

import os
import json
import time
import logging
import asyncio
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import argparse

# Dashboard libraries
import dash
from dash import dcc, html, callback, Output, Input, State
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Import visualization module
from secure_mcp_grpc.dashboard.visualization import TrafficVisualizer
from secure_mcp_grpc.telemetry.interaction_tracer import InteractionTracer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_REFRESH_INTERVAL = 5  # seconds
DEFAULT_TRACES_DIR = os.environ.get('TRACES_DIR', os.path.join(os.getcwd(), "traces"))
DEFAULT_PORT = int(os.environ.get('DASHBOARD_PORT', 8050))
DEFAULT_HOST = os.environ.get('DASHBOARD_HOST', '0.0.0.0')
DEFAULT_DEBUG = os.environ.get('DASH_DEBUG', 'false').lower() == 'true'


class DashboardApp:
    """
    Dashboard application for visualizing MCP-gRPC telemetry data.
    
    This class sets up a Dash web application with multiple views for
    visualizing different aspects of the telemetry data, including:
    - Traffic flow diagrams
    - Model interaction networks
    - Security event heatmaps
    - Performance metrics
    - Real-time monitoring
    """
    
    def __init__(
        self,
        traces_dir: str = DEFAULT_TRACES_DIR,
        refresh_interval: int = DEFAULT_REFRESH_INTERVAL,
        dashboard_title: str = "Secure MCP-gRPC Telemetry Dashboard"
    ):
        """
        Initialize the dashboard application.
        
        Args:
            traces_dir: Directory containing trace logs
            refresh_interval: How often to refresh visualizations (seconds)
            dashboard_title: Title for the dashboard
        """
        self.traces_dir = traces_dir
        self.refresh_interval = refresh_interval
        self.dashboard_title = dashboard_title
        
        # Initialize the interaction tracer
        self.tracer = InteractionTracer(
            storage_path=traces_dir,
            export_format="jsonl",
            encryption_key=None,  # Read-only access
            sanitize_fields=["password", "token", "secret", "key", "credential"],
            max_payload_size=1024 * 1024,  # 1MB
            sample_rate=1.0,
            enable_streaming=False
        )
        
        # Initialize the traffic visualizer
        self.visualizer = TrafficVisualizer(
            tracer=self.tracer,
            refresh_interval=refresh_interval,
            lookback_period=24  # hours
        )
        
        # Initialize the Dash app
        self.app = dash.Dash(
            __name__,
            external_stylesheets=[dbc.themes.DARKLY],
            meta_tags=[
                {"name": "viewport", "content": "width=device-width, initial-scale=1"}
            ]
        )
        self.app.title = dashboard_title
        
        # Create the layout
        self.create_layout()
        
        # Register callbacks
        self.register_callbacks()
        
        # Last update timestamp
        self.last_update = {
            "traffic_flow": 0,
            "interaction_network": 0,
            "security_heatmap": 0,
            "latency_distribution": 0,
            "real_time_metrics": 0
        }
        
        logger.info(f"Dashboard initialized with traces directory: {traces_dir}")
    
    def create_layout(self):
        """Create the dashboard layout with multiple tabs for different visualizations."""
        # Navigation bar
        navbar = dbc.Navbar(
            dbc.Container(
                [
                    html.A(
                        dbc.Row(
                            [
                                dbc.Col(html.Img(src="/assets/logo.png", height="30px")),
                                dbc.Col(dbc.NavbarBrand("Secure MCP-gRPC Dashboard", className="ms-2")),
                            ],
                            align="center",
                            className="g-0",
                        ),
                        href="/",
                        style={"textDecoration": "none"},
                    ),
                    dbc.NavbarToggler(id="navbar-toggler", n_clicks=0),
                    dbc.Collapse(
                        dbc.Nav(
                            [
                                dbc.NavItem(dbc.NavLink("Overview", href="#")),
                                dbc.NavItem(dbc.NavLink("Traffic Flow", href="#")),
                                dbc.NavItem(dbc.NavLink("Security", href="#")),
                                dbc.NavItem(dbc.NavLink("Performance", href="#")),
                                dbc.NavItem(dbc.NavLink("Settings", href="#")),
                            ],
                            className="ms-auto",
                            navbar=True,
                        ),
                        id="navbar-collapse",
                        navbar=True,
                    ),
                ],
                fluid=True,
            ),
            color="primary",
            dark=True,
            className="mb-4",
        )
        
        # Status indicators
        status_indicators = dbc.Row(
            [
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H5("System Status", className="card-title"),
                                html.Div(
                                    [
                                        html.Span("Operational", className="text-success"),
                                        html.I(className="fas fa-check-circle ms-2 text-success")
                                    ],
                                    id="system-status-indicator"
                                )
                            ]
                        ),
                        className="mb-4 shadow"
                    ),
                    width=3
                ),
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H5("Active Sessions", className="card-title"),
                                html.Div(
                                    [
                                        html.Span("0", id="active-sessions-count"),
                                        html.I(className="fas fa-users ms-2")
                                    ]
                                )
                            ]
                        ),
                        className="mb-4 shadow"
                    ),
                    width=3
                ),
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H5("Request Rate", className="card-title"),
                                html.Div(
                                    [
                                        html.Span("0", id="request-rate"),
                                        html.Span(" req/min", className="ms-1"),
                                        html.I(className="fas fa-chart-line ms-2")
                                    ]
                                )
                            ]
                        ),
                        className="mb-4 shadow"
                    ),
                    width=3
                ),
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H5("Security Alerts", className="card-title"),
                                html.Div(
                                    [
                                        html.Span("0", id="security-alerts-count"),
                                        html.I(className="fas fa-shield-alt ms-2 text-success")
                                    ],
                                    id="security-alerts-indicator"
                                )
                            ]
                        ),
                        className="mb-4 shadow"
                    ),
                    width=3
                ),
            ],
            className="mb-4"
        )
        
        # Time range selector
        time_range_selector = dbc.Card(
            dbc.CardBody(
                [
                    html.H5("Time Range", className="card-title"),
                    dbc.ButtonGroup(
                        [
                            dbc.Button("1h", id="btn-1h", color="primary", outline=True, n_clicks=0),
                            dbc.Button("3h", id="btn-3h", color="primary", outline=True, n_clicks=0),
                            dbc.Button("6h", id="btn-6h", color="primary", outline=True, n_clicks=0),
                            dbc.Button("12h", id="btn-12h", color="primary", outline=True, n_clicks=0),
                            dbc.Button("24h", id="btn-24h", color="primary", outline=True, n_clicks=1),
                        ],
                        id="time-range-buttons",
                        className="ms-auto"
                    ),
                    # Hidden