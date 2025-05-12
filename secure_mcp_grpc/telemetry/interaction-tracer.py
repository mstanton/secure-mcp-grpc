"""
Interaction Tracer for Model Context Protocol

This module provides comprehensive tracing and logging capabilities for model interactions
over MCP-gRPC. It captures detailed information about each interaction, including:
- Full request/response payloads (with configurable sanitization)
- Connection metadata and timing information
- Authentication and authorization decisions
- Path traversal for multi-model interactions
- Data lineage tracking
- Performance metrics

The data can be exported in various formats for analysis, visualization, and auditing.

Author: Claude
License: Apache 2.0
"""

import os
import uuid
import json
import time
import logging
import hashlib
import datetime
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor
import asyncio
import traceback

# Import cryptographic libraries for secure logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class InteractionEvent:
    """Base class for all interaction events."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = "base"
    session_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None


@dataclass
class RequestEvent(InteractionEvent):
    """Event representing an incoming request."""
    event_type: str = "request"
    method: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    user_id: Optional[str] = None
    client_ip: Optional[str] = None
    client_id: Optional[str] = None
    auth_type: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    request_size_bytes: Optional[int] = None


@dataclass
class ResponseEvent(InteractionEvent):
    """Event representing an outgoing response."""
    event_type: str = "response"
    request_id: str = ""
    result: Any = None
    error: Optional[Dict[str, Any]] = None
    processing_time_ms: int = 0
    token_count: Optional[int] = None
    response_size_bytes: Optional[int] = None


@dataclass
class SecurityEvent(InteractionEvent):
    """Event representing a security-related action."""
    event_type: str = "security"
    security_type: str = ""  # authentication, authorization, rate_limit, etc.
    user_id: Optional[str] = None
    client_ip: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    decision: bool = False
    reason: Optional[str] = None


@dataclass
class ExternalCallEvent(InteractionEvent):
    """Event representing a call to an external system."""
    event_type: str = "external_call"
    target_system: str = ""
    target_method: str = ""
    request_payload: Any = None
    response_payload: Any = None
    success: bool = True
    error_message: Optional[str] = None
    call_duration_ms: int = 0


@dataclass
class DataAccessEvent(InteractionEvent):
    """Event representing data access operations."""
    event_type: str = "data_access"
    data_type: str = ""
    operation: str = ""  # read, write, update, delete
    resource_id: Optional[str] = None
    record_count: Optional[int] = None
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class TraceContext:
    """Context for tracking chains of interactions."""
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    span_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_span_id: Optional[str] = None
    sampled: bool = True
    baggage: Dict[str, str] = field(default_factory=dict)


class InteractionTracer:
    """
    Main class for tracing model interactions.
    
    This tracer captures detailed information about model interactions, including
    request/response payloads, timing, authentication, and external calls.
    """
    
    def __init__(
        self,
        storage_path: Optional[str] = None,
        export_format: str = "jsonl",
        encryption_key: Optional[str] = None,
        sanitize_fields: Optional[List[str]] = None,
        max_payload_size: int = 1024 * 1024,  # 1MB default max payload size
        sample_rate: float = 1.0,  # 100% sampling by default
        enable_streaming: bool = False,
        stream_url: Optional[str] = None,
        max_workers: int = 5
    ):
        """
        Initialize the interaction tracer.
        
        Args:
            storage_path: Directory where trace logs will be stored
            export_format: Format for exporting traces (jsonl, csv, parquet, etc.)
            encryption_key: Key for encrypting sensitive data (if None, a key will be generated)
            sanitize_fields: List of field names to sanitize in logs
            max_payload_size: Maximum size of request/response payloads to log
            sample_rate: Percentage of interactions to trace (0.0-1.0)
            enable_streaming: Whether to stream traces to an external system
            stream_url: URL of the streaming destination
            max_workers: Maximum number of worker threads for async operations
        """
        self.storage_path = storage_path or os.path.join(os.getcwd(), "traces")
        self.export_format = export_format
        self.sanitize_fields = sanitize_fields or ["password", "token", "secret", "key", "credential"]
        self.max_payload_size = max_payload_size
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        self.enable_streaming = enable_streaming
        self.stream_url = stream_url
        
        # Ensure storage directory exists
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Set up encryption
        self.encryption_enabled = encryption_key is not None
        if self.encryption_enabled:
            self.setup_encryption(encryption_key)
        else:
            self.cipher = None
            
        # Set up thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Current trace contexts by session ID
        self.trace_contexts: Dict[str, TraceContext] = {}
        
        # For tracking model interaction chains
        self.interaction_graph: Dict[str, Set[str]] = {}
        
        # For data lineage tracking
        self.data_lineage: Dict[str, List[Tuple[str, str, str]]] = {}
        
        # Store open file handles for efficient writing
        self.file_handles: Dict[str, Any] = {}
        
        # Performance metrics
        self.performance_metrics = {
            "events_processed": 0,
            "events_dropped": 0,
            "processing_times": []
        }
        
        logger.info(f"Interaction tracer initialized with storage path: {self.storage_path}")
    
    def setup_encryption(self, key_material: str):
        """
        Set up encryption for sensitive data.
        
        Args:
            key_material: Material to derive the encryption key from
        """
        # Generate a key from the provided material
        salt = b'secure_mcp_tracer'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(key_material.encode()))
        self.cipher = Fernet(key)
        logger.info("Encryption set up for sensitive data in traces")
    
    def encrypt_value(self, value: str) -> str:
        """
        Encrypt a sensitive value.
        
        Args:
            value: The value to encrypt
            
        Returns:
            Encrypted value as a base64 string
        """
        if not self.encryption_enabled or not self.cipher:
            # Generate a secure hash instead of plaintext if encryption is disabled
            return f"HASHED:{hashlib.sha256(value.encode()).hexdigest()}"
        
        encrypted = self.cipher.encrypt(value.encode())
        return f"ENCRYPTED:{base64.urlsafe_b64encode(encrypted).decode()}"
    
    def sanitize_payload(self, payload: Any) -> Any:
        """
        Sanitize sensitive fields in the payload.
        
        Args:
            payload: The payload to sanitize
            
        Returns:
            Sanitized payload
        """
        if payload is None:
            return None
            
        if isinstance(payload, dict):
            result = {}
            for key, value in payload.items():
                # Check if this field should be sanitized
                if any(field in key.lower() for field in self.sanitize_fields):
                    if isinstance(value, str):
                        result[key] = "********"
                    elif isinstance(value, (list, dict)):
                        result[key] = f"[REDACTED {type(value).__name__}]"
                    else:
                        result[key] = f"[REDACTED]"
                else:
                    # Recursively sanitize nested structures
                    result[key] = self.sanitize_payload(value)
            return result
        elif isinstance(payload, list):
            return [self.sanitize_payload(item) for item in payload]
        else:
            return payload
    
    def truncate_payload(self, payload: Any) -> Any:
        """
        Truncate large payloads to the maximum size.
        
        Args:
            payload: The payload to truncate
            
        Returns:
            Truncated payload
        """
        if payload is None:
            return None
            
        # Convert to JSON to check size
        try:
            payload_json = json.dumps(payload)
            payload_size = len(payload_json.encode('utf-8'))
            
            if payload_size > self.max_payload_size:
                # Truncate and add metadata about truncation
                truncation_msg = f" ... [truncated, {payload_size} bytes total]"
                max_chars = self.max_payload_size // 4  # Rough estimate of bytes per char
                
                if isinstance(payload, dict):
                    # For dictionaries, include some key fields and truncate others
                    result = {
                        "__truncated": True,
                        "__original_size_bytes": payload_size,
                        "__truncation_reason": f"Exceeded max payload size of {self.max_payload_size} bytes"
                    }
                    
                    # Include essential fields if they exist
                    essential_fields = ["id", "method", "type", "status", "error"]
                    remaining_budget = max_chars
                    
                    for field in essential_fields:
                        if field in payload:
                            field_json = json.dumps(payload[field])
                            if len(field_json) <= remaining_budget:
                                result[field] = payload[field]
                                remaining_budget -= len(field_json)
                    
                    return result
                elif isinstance(payload, list):
                    # For lists, include a subset of items
                    max_items = max(1, self.max_payload_size // 1000)  # Rough estimate
                    truncated = payload[:max_items]
                    return truncated + [f"... {len(payload) - max_items} more items (truncated)"]
                elif isinstance(payload, str):
                    # For strings, truncate directly
                    return payload[:max_chars] + truncation_msg
                else:
                    # For other types, convert to string and truncate
                    return str(payload)[:max_chars] + truncation_msg
            
            return payload
        except Exception as e:
            # If payload can't be converted to JSON, return a placeholder
            logger.warning(f"Failed to truncate payload: {e}")
            return f"[Unparseable payload of type {type(payload).__name__}]"
    
    def should_sample(self) -> bool:
        """
        Determine if the current interaction should be sampled based on the sample rate.
        
        Returns:
            True if the interaction should be sampled, False otherwise
        """
        if self.sample_rate >= 1.0:
            return True
        elif self.sample_rate <= 0.0:
            return False
        else:
            return random.random() < self.sample_rate
    
    def get_or_create_trace_context(self, session_id: str, parent_context: Optional[TraceContext] = None) -> TraceContext:
        """
        Get or create a trace context for the given session.
        
        Args:
            session_id: The session ID
            parent_context: Optional parent trace context
            
        Returns:
            The trace context
        """
        if session_id not in self.trace_contexts:
            if parent_context:
                # Create a child span
                context = TraceContext(
                    trace_id=parent_context.trace_id,
                    parent_span_id=parent_context.span_id,
                    sampled=parent_context.sampled,
                    baggage=dict(parent_context.baggage)
                )
            else:
                # Create a new root trace
                context = TraceContext(sampled=self.should_sample())
            
            self.trace_contexts[session_id] = context
        
        return self.trace_contexts[session_id]
    
    async def record_event(self, event: InteractionEvent):
        """
        Record an interaction event.
        
        Args:
            event: The event to record
        """
        start_time = time.time()
        
        try:
            # Skip if not sampled
            if event.session_id in self.trace_contexts:
                context = self.trace_contexts[event.session_id]
                if not context.sampled:
                    self.performance_metrics["events_dropped"] += 1
                    return
            
            # Add trace information if not already present
            if event.session_id and not event.trace_id:
                context = self.get_or_create_trace_context(event.session_id)
                event.trace_id = context.trace_id
                event.span_id = context.span_id
                event.parent_span_id = context.parent_span_id
            
            # Process the event based on its type
            if isinstance(event, RequestEvent):
                await self._process_request_event(event)
            elif isinstance(event, ResponseEvent):
                await self._process_response_event(event)
            elif isinstance(event, SecurityEvent):
                await self._process_security_event(event)
            elif isinstance(event, ExternalCallEvent):
                await self._process_external_call_event(event)
            elif isinstance(event, DataAccessEvent):
                await self._process_data_access_event(event)
            else:
                # Generic event processing
                await self._write_event(event)
            
            # Update performance metrics
            self.performance_metrics["events_processed"] += 1
            processing_time = (time.time() - start_time) * 1000  # ms
            self.performance_metrics["processing_times"].append(processing_time)
            
            # Trim the processing times list if it gets too large
            if len(self.performance_metrics["processing_times"]) > 1000:
                self.performance_metrics["processing_times"] = self.performance_metrics["processing_times"][-1000:]
            
        except Exception as e:
            logger.error(f"Error recording event: {e}", exc_info=True)
            self.performance_metrics["events_dropped"] += 1
    
    async def _process_request_event(self, event: RequestEvent):
        """Process a request event."""
        # Sanitize and truncate the request parameters
        if event.params:
            event.params = self.truncate_payload(self.sanitize_payload(event.params))
            
            # Calculate request size
            try:
                event.request_size_bytes = len(json.dumps(event.params).encode('utf-8'))
            except Exception:
                pass
        
        # Record the event
        await self._write_event(event)
    
    async def _process_response_event(self, event: ResponseEvent):
        """Process a response event."""
        # Sanitize and truncate the response result
        if event.result:
            event.result = self.truncate_payload(self.sanitize_payload(event.result))
            
            # Calculate response size
            try:
                event.response_size_bytes = len(json.dumps(event.result).encode('utf-8'))
            except Exception:
                pass
        
        # Record the event
        await self._write_event(event)
    
    async def _process_security_event(self, event: SecurityEvent):
        """Process a security event."""
        # For security events, we want to ensure they're always recorded
        # but sensitive fields should be handled with care
        
        # Encrypt user ID if encryption is enabled
        if event.user_id and self.encryption_enabled:
            event.user_id = self.encrypt_value(event.user_id)
        
        # Record the event
        await self._write_event(event)
    
    async def _process_external_call_event(self, event: ExternalCallEvent):
        """Process an external call event."""
        # For external calls, track the interaction graph
        if event.session_id and event.target_system:
            source_node = event.session_id
            target_node = f"{event.target_system}:{event.target_method}"
            
            if source_node not in self.interaction_graph:
                self.interaction_graph[source_node] = set()
            
            self.interaction_graph[source_node].add(target_node)
        
        # Sanitize and truncate the request and response payloads
        if event.request_payload:
            event.request_payload = self.truncate_payload(self.sanitize_payload(event.request_payload))
        
        if event.response_payload:
            event.response_payload = self.truncate_payload(self.sanitize_payload(event.response_payload))
        
        # Record the event
        await self._write_event(event)
    
    async def _process_data_access_event(self, event: DataAccessEvent):
        """Process a data access event."""
        # For data access events, track data lineage
        if event.resource_id:
            if event.resource_id not in self.data_lineage:
                self.data_lineage[event.resource_id] = []
            
            self.data_lineage[event.resource_id].append((
                event.timestamp,
                event.operation,
                event.session_id or "unknown"
            ))
        
        # Record the event
        await self._write_event(event)
    
    async def _write_event(self, event: InteractionEvent):
        """
        Write an event to storage.
        
        Args:
            event: The event to write
        """
        # Convert the event to a serializable dictionary
        event_dict = asdict(event)
        
        # Add ISO timestamp for readability
        event_dict["timestamp_iso"] = datetime.datetime.fromtimestamp(
            event_dict["timestamp"]).isoformat()
        
        # Format the filename based on the day
        date_str = datetime.datetime.fromtimestamp(event.timestamp).strftime("%Y-%m-%d")
        filename = f"interactions_{date_str}.{self.export_format}"
        filepath = os.path.join(self.storage_path, filename)
        
        # Write the event to the file
        if self.export_format == "jsonl":
            await self._write_jsonl(filepath, event_dict)
        elif self.export_format == "csv":
            await self._write_csv(filepath, event_dict)
        else:
            logger.warning(f"Unsupported export format: {self.export_format}")
        
        # Stream the event if enabled
        if self.enable_streaming and self.stream_url:
            await self._stream_event(event_dict)
    
    async def _write_jsonl(self, filepath: str, event_dict: Dict[str, Any]):
        """Write an event in JSONL format."""
        # Use a thread pool to avoid blocking the event loop
        await asyncio.get_event_loop().run_in_executor(
            self.executor,
            self._write_jsonl_sync,
            filepath,
            event_dict
        )
    
    def _write_jsonl_sync(self, filepath: str, event_dict: Dict[str, Any]):
        """Synchronous version of _write_jsonl."""
        try:
            # Get or create the file handle
            if filepath not in self.file_handles:
                self.file_handles[filepath] = open(filepath, "a", encoding="utf-8")
            
            # Write the event as a JSON line
            self.file_handles[filepath].write(json.dumps(event_dict) + "\n")
            self.file_handles[filepath].flush()
        except Exception as e:
            logger.error(f"Error writing to {filepath}: {e}")
    
    async def _write_csv(self, filepath: str, event_dict: Dict[str, Any]):
        """Write an event in CSV format."""
        # Use a thread pool to avoid blocking the event loop
        await asyncio.get_event_loop().run_in_executor(
            self.executor,
            self._write_csv_sync,
            filepath,
            event_dict
        )
    
    def _write_csv_sync(self, filepath: str, event_dict: Dict[str, Any]):
        """Synchronous version of _write_csv."""
        try:
            import csv
            
            # Check if file exists and has header
            file_exists = os.path.exists(filepath) and os.path.getsize(filepath) > 0
            
            # Flatten nested dictionaries for CSV format
            flat_dict = self._flatten_dict(event_dict)
            
            # Get or create the file handle
            if filepath not in self.file_handles:
                self.file_handles[filepath] = open(filepath, "a", newline="", encoding="utf-8")
                csv_writer = csv.DictWriter(self.file_handles[filepath], fieldnames=flat_dict.keys())
                
                # Write header if the file is new
                if not file_exists:
                    csv_writer.writeheader()
            else:
                csv_writer = csv.DictWriter(self.file_handles[filepath], fieldnames=flat_dict.keys())
            
            # Write the event as a CSV row
            csv_writer.writerow(flat_dict)
            self.file_handles[filepath].flush()
        except Exception as e:
            logger.error(f"Error writing to {filepath}: {e}")
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        """Flatten a nested dictionary for CSV format."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))
        
        return dict(items)
    
    async def _stream_event(self, event_dict: Dict[str, Any]):
        """Stream an event to an external system."""
        if not self.stream_url:
            return
        
        # Use a thread pool to avoid blocking the event loop
        await asyncio.get_event_loop().run_in_executor(
            self.executor,
            self._stream_event_sync,
            event_dict
        )
    
    def _stream_event_sync(self, event_dict: Dict[str, Any]):
        """Synchronous version of _stream_event."""
        try:
            import requests
            
            # Send the event to the streaming endpoint
            response = requests.post(
                self.stream_url,
                json=event_dict,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code >= 400:
                logger.warning(
                    f"Failed to stream event: HTTP {response.status_code} - {response.text}"
                )
        except Exception as e:
            logger.warning(f"Error streaming event: {e}")
    
    async def record_request(
        self,
        method: str,
        params: Dict[str, Any],
        session_id: str,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        client_id: Optional[str] = None,
        auth_type: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Record a request event.
        
        Args:
            method: The method being called
            params: The request parameters
            session_id: The session ID
            user_id: The user ID
            client_ip: The client IP address
            client_id: The client ID
            auth_type: The authentication type
            headers: The request headers
            
        Returns:
            The event ID
        """
        event = RequestEvent(
            session_id=session_id,
            method=method,
            params=params,
            user_id=user_id,
            client_ip=client_ip,
            client_id=client_id,
            auth_type=auth_type,
            headers=headers or {}
        )
        
        await self.record_event(event)
        return event.id
    
    async def record_response(
        self,
        request_id: str,
        result: Any,
        session_id: str,
        processing_time_ms: int,
        error: Optional[Dict[str, Any]] = None,
        token_count: Optional[int] = None
    ) -> str:
        """
        Record a response event.
        
        Args:
            request_id: The corresponding request ID
            result: The response result
            session_id: The session ID
            processing_time_ms: The processing time in milliseconds
            error: Optional error information
            token_count: Optional token count
            
        Returns:
            The event ID
        """
        event = ResponseEvent(
            session_id=session_id,
            request_id=request_id,
            result=result,
            error=error,
            processing_time_ms=processing_time_ms,
            token_count=token_count
        )
        
        await self.record_event(event)
        return event.id
    
    async def record_security_event(
        self,
        security_type: str,
        decision: bool,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        reason: Optional[str] = None
    ) -> str:
        """
        Record a security event.
        
        Args:
            security_type: The type of security event
            decision: Whether the action was allowed
            session_id: The session ID
            user_id: The user ID
            client_ip: The client IP address
            resource: The resource being accessed
            action: The action being performed
            reason: The reason for the decision
            
        Returns:
            The event ID
        """
        event = SecurityEvent(
            session_id=session_id,
            security_type=security_type,
            user_id=user_id,
            client_ip=client_ip,
            resource=resource,
            action=action,
            decision=decision,
            reason=reason
        )
        
        await self.record_event(event)
        return event.id
    
    async def record_external_call(
        self,
        target_system: str,
        target_method: str,
        session_id: Optional[str] = None,
        request_payload: Any = None,
        response_payload: Any = None,
        success: bool = True,
        error_message: Optional[str] = None,
        call_duration_ms: int = 0
    ) -> str:
        """
        Record an external call event.
        
        Args:
            target_system: The target system
            target_method: The target method
            session_id: The session ID
            request_payload: The request payload
            response_payload: The response payload
            success: Whether the call was successful
            error_message: Optional error message
            call_duration_ms: The call duration in milliseconds
            
        Returns:
            The event ID
        """
        event = ExternalCallEvent(
            session_id=session_id,
            target_system=target_system,
            target_method=target_method,
            request_payload=request_payload,
            response_payload=response_payload,
            success=success,
            error_message=error_message,
            call_duration_ms=call_duration_ms
        )
        
        await self.record_event(event)
        return event.id
    
    async def record_data_access(
        self,
        data_type: str,
        operation: str,
        session_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        record_count: Optional[int] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> str:
        """
        Record a data access event.
        
        Args:
            data_type: The type of data
            operation: The operation being performed
            session_id: The session ID
            resource_id: The resource ID
            record_count: The number of records accessed
            success: Whether the operation was successful
            error_message: Optional error message
            
        Returns:
            The event ID
        """
        event = DataAccessEvent(
            session_id=session_id,
            data_type=data_type,
            operation=operation,
            resource_id=resource_id,
            record_count=record_count,
            success=success,
            error_message=error_message
        )
        
        await self.record_event(event)
        return event.id
    
    def get_model_interaction_graph(self) -> Dict[str, Set[str]]:
        """
        Get the model interaction graph.
        
        Returns:
            Dictionary mapping source nodes to sets of target nodes
        """
        return self.interaction_graph
    
    def get_data_lineage(self) -> Dict[str, List[Tuple[str, str, str]]]:
        """
        Get the data lineage information.
        
        Returns:
            Dictionary mapping resource IDs to lists of (timestamp, operation, session_id) tuples
        """
        return self.data_lineage
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get performance metrics for the tracer.
        
        Returns:
            Dictionary of performance metrics
        """
        metrics = dict(self.performance_metrics)
        
        # Calculate average processing time
        if metrics["processing_times"]:
            metrics["avg_processing_time_ms"] = sum(metrics["processing_times"]) / len(metrics["processing_times"])
        else: