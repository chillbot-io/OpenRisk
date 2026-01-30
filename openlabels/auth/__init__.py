"""
OpenLabels Authentication & Authorization.

Provides user management, JWT sessions, encrypted vaults, and admin recovery.

Usage:
    from openlabels.auth import AuthManager

    auth = AuthManager()

    # First-time setup (creates admin)
    if auth.needs_setup():
        recovery_keys = auth.setup_admin("admin", "password123", email="admin@example.com")
        # Save recovery_keys securely!

    # Login
    session = auth.login("admin", "password123")

    # Access vault
    vault = session.get_vault()
    vault.store_spans(file_hash, spans)

    # Logout
    auth.logout(session.token)
"""

from .models import User, Session, UserRole
from .users import UserManager
from .jwt import JWTManager
from .recovery import RecoveryManager
from .crypto import CryptoProvider

__all__ = [
    "AuthManager",
    "User",
    "Session",
    "UserRole",
    "UserManager",
    "JWTManager",
    "RecoveryManager",
    "CryptoProvider",
]


class AuthManager:
    """
    Main entry point for authentication operations.

    Coordinates user management, JWT tokens, and recovery keys.
    Thread-safe for use from Qt GUI.
    """

    def __init__(self, data_dir: str | None = None):
        """
        Initialize auth manager.

        Args:
            data_dir: Base directory for auth data. Defaults to ~/.openlabels/
        """
        from pathlib import Path

        self._data_dir = Path(data_dir) if data_dir else Path.home() / ".openlabels"
        self._crypto = CryptoProvider()
        self._users = UserManager(self._data_dir / "users", self._crypto)
        self._jwt = JWTManager(self._data_dir / "jwt_secret")
        self._recovery = RecoveryManager(self._data_dir / "recovery", self._crypto)
        self._active_sessions: dict[str, Session] = {}

    def needs_setup(self) -> bool:
        """Check if first-time setup is needed (no admin exists)."""
        return not self._users.admin_exists()

    def setup_admin(
        self,
        username: str,
        password: str,
        email: str | None = None,
        subscribe_updates: bool = True,
    ) -> list[str]:
        """
        First-time setup: create admin user.

        Args:
            username: Admin username
            password: Admin password
            email: Optional email for updates
            subscribe_updates: Whether to subscribe to OpenLabels updates

        Returns:
            List of recovery keys (save these securely!)

        Raises:
            RuntimeError: If admin already exists
        """
        raise NotImplementedError("Scaffold - to be implemented")

    def create_user(
        self,
        admin_session: Session,
        username: str,
        password: str,
        role: UserRole = UserRole.USER,
    ) -> User:
        """
        Create a new user (admin only).

        Args:
            admin_session: Authenticated admin session
            username: New user's username
            password: New user's password
            role: User role (default: USER)

        Returns:
            Created User object

        Raises:
            PermissionError: If session is not admin
            ValueError: If username already exists
        """
        raise NotImplementedError("Scaffold - to be implemented")

    def login(self, username: str, password: str) -> Session:
        """
        Authenticate user and create session.

        Args:
            username: Username
            password: Password

        Returns:
            Authenticated Session with JWT token

        Raises:
            AuthenticationError: If credentials invalid
        """
        raise NotImplementedError("Scaffold - to be implemented")

    def logout(self, token: str) -> None:
        """
        End a session.

        Args:
            token: JWT token to invalidate
        """
        raise NotImplementedError("Scaffold - to be implemented")

    def verify_session(self, token: str) -> Session | None:
        """
        Verify a JWT token and return session if valid.

        Args:
            token: JWT token

        Returns:
            Session if valid, None otherwise
        """
        raise NotImplementedError("Scaffold - to be implemented")

    def reset_user_vault(self, admin_session: Session, username: str) -> None:
        """
        Reset a user's vault (admin only). User loses vault data.

        Args:
            admin_session: Authenticated admin session
            username: User whose vault to reset

        Raises:
            PermissionError: If session is not admin
        """
        raise NotImplementedError("Scaffold - to be implemented")

    def recover_with_key(self, recovery_key: str, new_password: str) -> bool:
        """
        Recover admin account using recovery key.

        Args:
            recovery_key: One of the admin recovery keys
            new_password: New password to set

        Returns:
            True if recovery successful
        """
        raise NotImplementedError("Scaffold - to be implemented")
