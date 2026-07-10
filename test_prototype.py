#!/usr/bin/env python3
"""
Test script for the DAVINCI prototype

This script demonstrates the basic functionality of the DAVINCI prototype
by running the demo scenario.
"""

import subprocess
import time
import sys
import os

def main():
    print("DAVINCI Prototype Test")
    print("=" * 50)
    
    # Change to the demo directory
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo"))
    
    # Run the demo scenario
    print("Running DAVINCI demo scenario...")
    try:
        result = subprocess.run([sys.executable, "demo_scenario.py"], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("Demo completed successfully!")
            print("Output:")
            print(result.stdout)
        else:
            print("Demo failed with return code:", result.returncode)
            print("Error output:")
            print(result.stderr)
            
    except subprocess.TimeoutExpired:
        print("Demo timed out after 30 seconds")
    except Exception as e:
        print(f"Error running demo: {e}")

if __name__ == "__main__":
    main()