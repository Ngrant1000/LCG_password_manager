# security_utils.py

import os
import sys
import platform
import ctypes
import hashlib
import time
import logging
import threading
import winreg
import psutil
from pathlib import Path
from typing import Optional, List, Dict, Any

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(
            os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "LCGPasswordManager", "security.log"),
            mode='a'
        )
    ]
)

# Security constants
INTEGRITY_CHECK_INTERVAL = 5  # seconds
MEMORY_CHECK_INTERVAL = 2  # seconds
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # 5 minutes

class SecurityMonitor:
    """Monitors application integrity and security."""
    
    def __init__(self):
        self._original_hashes = {}
        self._failed_attempts = 0
        self._lockout_until = 0
        self._running = False
        self._monitor_thread = None
        self._memory_thread = None
        self._debugger_detected = False
        self._network_access = False
        self._audit_events = []
        
        # Initialize security measures
        self._disable_network_access()
        self._calculate_original_hashes()
        self._start_monitoring()
    
    def _calculate_original_hashes(self) -> None:
        """Calculate hashes of critical files for integrity checking."""
        critical_files = [
            "main.py",
            "gui.py",
            "encryption_utils.py",
            "data_manager.py",
            "security_utils.py"
        ]
        
        for file in critical_files:
            try:
                with open(file, 'rb') as f:
                    content = f.read()
                    self._original_hashes[file] = hashlib.sha256(content).hexdigest()
            except Exception as e:
                logging.error(f"Failed to calculate hash for {file}: {e}")
    
    def _check_file_integrity(self) -> bool:
        """Check if critical files have been modified."""
        for file, original_hash in self._original_hashes.items():
            try:
                with open(file, 'rb') as f:
                    content = f.read()
                    current_hash = hashlib.sha256(content).hexdigest()
                    if current_hash != original_hash:
                        logging.critical(f"File integrity check failed for {file}")
                        self._log_security_event("INTEGRITY_FAILURE", f"File {file} has been modified")
                        return False
            except Exception as e:
                logging.error(f"Failed to check integrity of {file}: {e}")
                return False
        return True
    
    def _check_process_integrity(self) -> bool:
        """Check for debugging and process injection attempts."""
        if platform.system() == "Windows":
            # Check for debugger
            is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
            if is_debugger_present:
                logging.critical("Debugger detected")
                self._log_security_event("DEBUGGER_DETECTED", "A debugger was detected")
                return False
                
            # Check for common debugging tools
            suspicious_processes = [
                "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
                "ida.exe", "ida64.exe", "idag.exe", "idag64.exe", "idaw.exe",
                "idaw64.exe", "immunity debugger.exe", "immunity debugger 64.exe"
            ]
            
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'].lower() in suspicious_processes:
                        logging.critical(f"Suspicious process detected: {proc.info['name']}")
                        self._log_security_event("SUSPICIOUS_PROCESS", f"Process {proc.info['name']} detected")
                        return False
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        return True
    
    def _check_memory_integrity(self) -> bool:
        """Check for memory tampering."""
        # This is a simplified check - in a real app, you'd implement more sophisticated checks
        try:
            # Check if our security monitor is still running
            if not self._running:
                logging.critical("Security monitor was stopped")
                self._log_security_event("MONITOR_STOPPED", "Security monitor was stopped")
                return False
                
            # Check if our critical functions are still in memory
            # This is a basic check and could be enhanced
            if not hasattr(self, '_check_file_integrity') or not hasattr(self, '_check_process_integrity'):
                logging.critical("Critical functions missing from memory")
                self._log_security_event("MEMORY_TAMPERING", "Critical functions missing from memory")
                return False
        except Exception as e:
            logging.error(f"Memory integrity check failed: {e}")
            return False
        return True
    
    def _disable_network_access(self) -> None:
        """Disable network access to prevent data exfiltration."""
        try:
            if platform.system() == "Windows":
                # Disable network adapters
                import win32com.client
                wmi = win32com.client.GetObject("winmgmts:")
                adapters = wmi.InstancesOf("Win32_NetworkAdapter")
                for adapter in adapters:
                    if adapter.NetEnabled:
                        adapter.Disable()
                        logging.info(f"Disabled network adapter: {adapter.Name}")
            else:
                # Unix-like systems
                os.system("ifconfig eth0 down")
                os.system("ifconfig wlan0 down")
                logging.info("Disabled network interfaces")
            
            self._network_access = False
            self._log_security_event("NETWORK_DISABLED", "Network access disabled")
        except Exception as e:
            logging.error(f"Failed to disable network: {e}")
    
    def _log_security_event(self, event_type: str, details: str) -> None:
        """Log security events for audit."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        event = {
            "timestamp": timestamp,
            "type": event_type,
            "details": details,
            "pid": os.getpid(),
            "username": os.getenv("USERNAME") or os.getenv("USER")
        }
        self._audit_events.append(event)
        logging.info(f"Security event: {event_type} - {details}")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                # Check file integrity
                if not self._check_file_integrity():
                    self._handle_security_violation("File integrity check failed")
                
                # Check process integrity
                if not self._check_process_integrity():
                    self._handle_security_violation("Process integrity check failed")
                
                # Sleep for the check interval
                time.sleep(INTEGRITY_CHECK_INTERVAL)
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
    
    def _memory_check_loop(self) -> None:
        """Memory integrity check loop."""
        while self._running:
            try:
                # Check memory integrity
                if not self._check_memory_integrity():
                    self._handle_security_violation("Memory integrity check failed")
                
                # Sleep for the check interval
                time.sleep(MEMORY_CHECK_INTERVAL)
            except Exception as e:
                logging.error(f"Error in memory check loop: {e}")
    
    def _handle_security_violation(self, reason: str) -> None:
        """Handle security violations."""
        self._failed_attempts += 1
        self._log_security_event("SECURITY_VIOLATION", reason)
        
        if self._failed_attempts >= MAX_FAILED_ATTEMPTS:
            self._lockout_until = time.time() + LOCKOUT_DURATION
            self._log_security_event("LOCKOUT", f"Application locked for {LOCKOUT_DURATION} seconds")
            
            # In a real app, you might want to exit or lock the UI
            # For now, we'll just log the event
            logging.critical(f"Application locked: {reason}")
    
    def _start_monitoring(self) -> None:
        """Start the security monitoring threads."""
        self._running = True
        
        # Start integrity monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        # Start memory monitoring thread
        self._memory_thread = threading.Thread(target=self._memory_check_loop, daemon=True)
        self._memory_thread.start()
        
        logging.info("Security monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop the security monitoring."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)
        if self._memory_thread:
            self._memory_thread.join(timeout=1.0)
        logging.info("Security monitoring stopped")
    
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get the audit log."""
        return self._audit_events.copy()
    
    def is_locked(self) -> bool:
        """Check if the application is locked due to security violations."""
        if self._failed_attempts >= MAX_FAILED_ATTEMPTS:
            if time.time() < self._lockout_until:
                return True
            else:
                # Reset after lockout period
                self._failed_attempts = 0
        return False

# Create a global instance
security_monitor = SecurityMonitor() 