"""Projects: the unit that owns key bundles, datasets and jobs."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit.service import AuditAction
from ..db.models import Project, Role
from ..deps import Principal, db_session, get_state, require
from ..errors import ConflictError
from ..schemas import Page, ProjectCreate, ProjectOut, ProjectUpdate
from ..storage.objects import ObjectStore
from .common import audit, page_of, paginate

router = APIRouter(prefix="/v1/projects", tags=["projects"])


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectCreate,
    request: Request,
    principal: Principal = Depends(require("projects:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> Project:
    tenant = principal.tenant(session)
    project = tenant.add(Project(name=body.name, description=body.description, created_by_user_id=principal.user_id))
    try:
        await tenant.flush()
    except IntegrityError:
        raise ConflictError("a project with this name already exists") from None
    await audit(request, tenant, principal, AuditAction.PROJECT_CREATED, "project", project.id, name=project.name)
    await tenant.commit()
    return project


@router.get("", response_model=Page[ProjectOut])
async def list_projects(
    limit: int = Query(50),
    before: str | None = Query(None),
    principal: Principal = Depends(require("projects:read")),
    session: AsyncSession = Depends(db_session),
) -> Page[ProjectOut]:
    tenant = principal.tenant(session)
    rows = list(await tenant.scalars(paginate(tenant.select(Project), Project.id, limit=limit, before=before)))
    items, cursor = page_of(rows, limit)
    return Page[ProjectOut](items=[ProjectOut.model_validate(p) for p in items], next_cursor=cursor)


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: uuid.UUID,
    principal: Principal = Depends(require("projects:read")),
    session: AsyncSession = Depends(db_session),
) -> Project:
    return await principal.tenant(session).get_or_404(Project, project_id, "project")


@router.patch("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdate,
    request: Request,
    principal: Principal = Depends(require("projects:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> Project:
    tenant = principal.tenant(session)
    project = await tenant.get_or_404(Project, project_id, "project")
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(project, key, value)
    try:
        await tenant.flush()
    except IntegrityError:
        raise ConflictError("a project with this name already exists") from None
    await audit(request, tenant, principal, AuditAction.PROJECT_UPDATED, "project", project.id, fields=sorted(changes))
    await tenant.commit()
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("projects:write", Role.ADMIN)),
    session: AsyncSession = Depends(db_session),
) -> None:
    tenant = principal.tenant(session)
    project = await tenant.get_or_404(Project, project_id, "project")
    await tenant.delete(project)
    await audit(request, tenant, principal, AuditAction.PROJECT_DELETED, "project", project_id, name=project.name)
    await tenant.commit()
    prefix = f"{ObjectStore.tenant_prefix(principal.organization_id)}projects/{project_id}/"
    await get_state(request).store.delete_prefix(prefix, principal.organization_id)
