"""
OpenLabels GUI entry point.

Usage:
    openlabels gui
    openlabels gui --path /data
"""

import sys
from typing import Optional


def launch_gui(initial_path: Optional[str] = None) -> int:
    """Launch the OpenLabels GUI application."""
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import Qt
    except ImportError:
        print("Error: PySide6 is required for the GUI.")
        print("Install it with: pip install PySide6")
        return 1

    from openlabels.gui.main_window import MainWindow

    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("OpenLabels")
    app.setOrganizationName("OpenLabels")
    app.setOrganizationDomain("openlabels.dev")

    # Set application style
    app.setStyle("Fusion")

    window = MainWindow(initial_path=initial_path)
    window.show()

    return app.exec()


def main():
    """CLI entry point for GUI."""
    import argparse

    parser = argparse.ArgumentParser(description="OpenLabels GUI")
    parser.add_argument("--path", "-p", help="Initial path to load")
    args = parser.parse_args()

    sys.exit(launch_gui(initial_path=args.path))


if __name__ == "__main__":
    main()
