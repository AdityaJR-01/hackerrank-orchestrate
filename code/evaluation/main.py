"""Convenience entry point for the team-created custom evaluation cases."""
import runpy
from pathlib import Path

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).with_name("run_custom_cases.py")), run_name="__main__")
