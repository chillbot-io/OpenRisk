"""
OpenLabels GUI entry point.

Usage:
    openlabels gui
    openlabels gui --path /data
    openlabels gui --no-server  # Disable auto-start of backend server
"""

import sys
from typing import Optional


def launch_gui(initial_path: Optional[str] = None, use_server: bool = True) -> int:
    """Launch the OpenLabels GUI application.

    Args:
        initial_path: Path to load on startup
        use_server: If True, auto-start the async backend server for better performance
    """
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import Qt
    except ImportError:
        print("Error: PySide6 is required for the GUI.")
        print("Install it with: pip install PySide6")
        return 1

    # Try to start backend server for better responsiveness
    server_url = None
    if use_server:
        try:
            from openlabels.gui.backend_manager import start_backend
            server_url = start_backend()
            if server_url:
                print(f"Backend server started: {server_url}")
            else:
                print("Backend server not available, using in-process scanning")
        except ImportError:
            pass  # Server dependencies not installed

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

    window = MainWindow(initial_path=initial_path, server_url=server_url)
    window.show()

    result = app.exec()

    # Cleanup backend server
    if server_url:
        try:
            from openlabels.gui.backend_manager import stop_backend
            stop_backend()
        except ImportError:
            pass

    return result


def main():
    """CLI entry point for GUI."""
    import argparse

    parser = argparse.ArgumentParser(description="OpenLabels GUI")
    parser.add_argument("--path", "-p", help="Initial path to load")
    parser.add_argument(
        "--no-server", action="store_true",
        help="Disable auto-start of backend server (use in-process scanning)"
    )
    args = parser.parse_args()

    sys.exit(launch_gui(initial_path=args.path, use_server=not args.no_server))


if __name__ == "__main__":
    main()
