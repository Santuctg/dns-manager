from __future__ import annotations

import argparse
import getpass
from contextlib import contextmanager

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import SessionLocal, get_engine
from app.models.auth import Role, User
from app.security import hash_password

MIN_PASSWORD_LENGTH = 12


def _validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")


def create_superadmin(
    db: Session,
    username: str,
    email: str | None,
    password: str,
) -> User:
    username = username.strip()
    email = email.strip().lower() if email and email.strip() else None
    if not username:
        raise ValueError("username is required")
    _validate_password(password)

    if db.scalar(select(User).where(User.username == username)) is not None:
        raise ValueError("username already exists")
    if email and db.scalar(select(User).where(User.email == email)) is not None:
        raise ValueError("email already exists")

    role = db.scalar(select(Role).where(Role.name == "super_admin"))
    if role is None:
        raise ValueError("super_admin role is missing; run database migrations first")

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_active=True,
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def reset_password(db: Session, username: str, password: str) -> User:
    _validate_password(password)
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None:
        raise ValueError("user not found")

    user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    db.commit()
    db.refresh(user)
    return user


def get_db_session() -> Session:
    return SessionLocal(bind=get_engine())


def _prompt_password(confirm: bool = True) -> str:
    password = getpass.getpass("Password: ")
    if confirm:
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("passwords do not match")
    return password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dns-manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("create-superadmin", help="Create the initial Super Admin account")

    reset = subparsers.add_parser("reset-password", help="Reset a user's password")
    reset.add_argument("username")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    db = get_db_session()
    try:
        if args.command == "create-superadmin":
            username = input("Username: ").strip()
            email = input("Email (optional): ").strip() or None
            password = _prompt_password(confirm=True)
            user = create_superadmin(db, username, email, password)
            print(f"Super Admin created: {user.username}")
            return 0

        if args.command == "reset-password":
            password = _prompt_password(confirm=True)
            user = reset_password(db, args.username, password)
            print(f"Password reset: {user.username}")
            return 0

        parser.error("unknown command")
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
