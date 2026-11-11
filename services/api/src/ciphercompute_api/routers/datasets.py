"""Datasets: a named group of ciphertexts encrypted under one key bundle."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit.service import AuditAction
from ..db.models import Dataset, KeyBundle, KeyBundleStatus, Project, Role
from ..deps import Principal, db_session, get_state, require
from ..errors import ConflictError, UnprocessableError
from ..schemas import DatasetCreate, DatasetOut, Page
from ..storage.objects import ObjectStore
from .common import audit, page_of, paginate

router = APIRouter(prefix="/v1", tags=["datasets"])


@router.post("/projects/{project_id}/datasets", response_model=DatasetOut, status_code=status.HTTP_201_CREATED)
async def create_dataset(
    project_id: uuid.UUID,
    body: DatasetCreate,
    request: Request,
    principal: Principal = Depends(require("datasets:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> Dataset:
    tenant = principal.tenant(session)
    await tenant.get_or_404(Project, project_id, "project")
    bundle = await tenant.get_or_404(KeyBundle, body.key_bundle_id, "key bundle")
    if bundle.project_id != project_id:
        raise UnprocessableError("key bundle belongs to a different project")
    if bundle.status != KeyBundleStatus.ACTIVE:
        raise UnprocessableError("key bundle is not active", status=bundle.status.value)
    dataset = tenant.add(
        Dataset(project_id=project_id, key_bundle_id=bundle.id, name=body.name, description=body.description)
    )
    try:
        await tenant.flush()
    except IntegrityError:
        raise ConflictError("a dataset with this name already exists in the project") from None
    await audit(request, tenant, principal, AuditAction.DATASET_CREATED, "dataset", dataset.id, name=dataset.name)
    await tenant.commit()
    return dataset


@router.get("/projects/{project_id}/datasets", response_model=Page[DatasetOut])
async def list_datasets(
    project_id: uuid.UUID,
    limit: int = Query(50),
    before: str | None = Query(None),
    principal: Principal = Depends(require("datasets:read")),
    session: AsyncSession = Depends(db_session),
) -> Page[DatasetOut]:
    tenant = principal.tenant(session)
    await tenant.get_or_404(Project, project_id, "project")
    stmt = paginate(
        tenant.select(Dataset).where(Dataset.project_id == project_id), Dataset.id, limit=limit, before=before
    )
    items, cursor = page_of(list(await tenant.scalars(stmt)), limit)
    return Page[DatasetOut](items=[DatasetOut.model_validate(d) for d in items], next_cursor=cursor)


@router.get("/datasets/{dataset_id}", response_model=DatasetOut)
async def get_dataset(
    dataset_id: uuid.UUID,
    principal: Principal = Depends(require("datasets:read")),
    session: AsyncSession = Depends(db_session),
) -> Dataset:
    return await principal.tenant(session).get_or_404(Dataset, dataset_id, "dataset")


@router.delete("/datasets/{dataset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dataset(
    dataset_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require("datasets:write", Role.ANALYST)),
    session: AsyncSession = Depends(db_session),
) -> None:
    tenant = principal.tenant(session)
    dataset = await tenant.get_or_404(Dataset, dataset_id, "dataset")
    project_id = dataset.project_id
    await tenant.delete(dataset)
    await audit(request, tenant, principal, AuditAction.DATASET_DELETED, "dataset", dataset_id, name=dataset.name)
    await tenant.commit()
    prefix = f"{ObjectStore.tenant_prefix(principal.organization_id)}projects/{project_id}/datasets/{dataset_id}/"
    await get_state(request).store.delete_prefix(prefix, principal.organization_id)
