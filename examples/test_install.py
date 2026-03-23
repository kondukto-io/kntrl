"""Dummy install script for testing kntrl file and process monitoring."""

import os
import subprocess

def setup():
    print("hello world")
    print(f"Running as PID: {os.getpid()}")
    print("Install complete.")

if __name__ == "__main__":
    setup()
