from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models.auth import Role, User
from app.security import SESSION_COOKIE
from app.services.auth_service import has_permission, resolve_session


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    session_data = request.scope.get("session")
    user_id = session_data.get("user_id") if session_data else None
    if not isinstance(user_id, int):
        raw_session = request.cookies.get(SESSION_COOKIE)
        if not raw_session:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
        resolved = resolve_session(db, raw_session)
        if resolved is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
        user_id = resolved.user_id

    stmt = (
        select(User)
        .options(selectinload(User.role).selectinload(Role.permissions))
        .where(User.id == user_id)
    )
    user = db.scalar(stmt)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
    return user


def require_permission(permission_name: str) -> Callable[[User], User]:
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user, permission_name):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
        return current_user

    return dependency
