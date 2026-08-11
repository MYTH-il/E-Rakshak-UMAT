from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from umat.audit import append_audit
from umat.auth.dependencies import Principal, current_principal, require_roles
from umat.db import get_db
from umat.db.models import (
    WindowsProfileOperation,
    WindowsProfileOperationState,
    WindowsProfileOperationType,
    WindowsProfileState,
    WindowsVMProfile,
)
from umat.windows.schemas import (
    CreateWindowsProfileRequest,
    UpdateWindowsProfileRequest,
    WindowsProfileActionResponse,
    WindowsProfileDetailResponse,
    WindowsProfileOperationResponse,
    WindowsProfileResponse,
)

router = APIRouter(prefix="/api/v1/windows/profiles", tags=["windows-profiles"])


def response(profile: WindowsVMProfile) -> WindowsProfileResponse:
    return WindowsProfileResponse(
        id=profile.id,
        name=profile.name,
        display_name=profile.display_name,
        state=profile.state.value,
        windows_version=profile.windows_version,
        architecture=profile.architecture,
        vcpus=profile.vcpus,
        ram_mb=profile.ram_mb,
        disk_gb=profile.disk_gb,
        user_profile=profile.user_profile,
        analysis_profile=profile.analysis_profile,
        cape_machine_label=profile.cape_machine_label,
        cape_template=profile.cape_template,
        is_default=profile.is_default,
        created_at=profile.created_at,
        retired_at=profile.retired_at,
        error_detail=profile.error_detail,
    )


async def active_profile(db: AsyncSession, profile_id: UUID) -> WindowsVMProfile:
    profile = await db.get(WindowsVMProfile, profile_id, with_for_update=True)
    if not profile or profile.state != WindowsProfileState.ACTIVE:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "active Windows profile not found")
    return profile


@router.get("", response_model=list[WindowsProfileResponse])
async def list_profiles(
    include_inactive: bool = Query(False),
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> list[WindowsProfileResponse]:
    query = select(WindowsVMProfile).order_by(WindowsVMProfile.name)
    if "administrator" not in principal.roles or not include_inactive:
        query = query.where(WindowsVMProfile.state == WindowsProfileState.ACTIVE)
    return [response(item) for item in (await db.scalars(query)).all()]


@router.get("/{profile_id}", response_model=WindowsProfileDetailResponse)
async def get_profile(
    profile_id: UUID,
    _: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> WindowsProfileDetailResponse:
    profile = await db.get(WindowsVMProfile, profile_id)
    if not profile:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Windows profile not found")
    operations = list(
        (
            await db.scalars(
                select(WindowsProfileOperation)
                .where(WindowsProfileOperation.profile_id == profile.id)
                .order_by(WindowsProfileOperation.created_at.desc())
            )
        ).all()
    )
    return WindowsProfileDetailResponse(
        profile=response(profile),
        operations=[
            WindowsProfileOperationResponse(
                id=item.id,
                operation_type=item.operation_type.value,
                state=item.state.value,
                executor_id=item.executor_id,
                native_operation_id=item.native_operation_id,
                result=item.result,
                error_detail=item.error_detail,
                created_at=item.created_at,
                completed_at=item.completed_at,
            )
            for item in operations
        ],
    )


@router.patch("/{profile_id}", response_model=WindowsProfileResponse)
async def update_profile(
    profile_id: UUID,
    body: UpdateWindowsProfileRequest,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> WindowsProfileResponse:
    profile = await active_profile(db, profile_id)
    before = {
        "display_name": profile.display_name,
        "analysis_profile": profile.analysis_profile,
        "is_default": profile.is_default,
    }
    if "display_name" in body.model_fields_set and body.display_name:
        profile.display_name = body.display_name.strip()
    if "analysis_profile" in body.model_fields_set and body.analysis_profile:
        profile.analysis_profile = body.analysis_profile
    if body.is_default is not None:
        if body.is_default:
            await db.execute(
                update(WindowsVMProfile)
                .where(WindowsVMProfile.id != profile.id)
                .values(is_default=False)
            )
        profile.is_default = body.is_default
    after = {
        "display_name": profile.display_name,
        "analysis_profile": profile.analysis_profile,
        "is_default": profile.is_default,
    }
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="windows_profile.updated",
        target_type="windows_vm_profile",
        target_id=str(profile.id),
        payload={"before": before, "after": after},
    )
    await db.commit()
    return response(profile)


@router.post("", response_model=WindowsProfileActionResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_profile(
    body: CreateWindowsProfileRequest,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> WindowsProfileActionResponse:
    if await db.scalar(select(WindowsVMProfile).where(WindowsVMProfile.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "profile name already exists")
    if body.is_default:
        await db.execute(update(WindowsVMProfile).values(is_default=False))
    profile = WindowsVMProfile(
        name=body.name,
        display_name=body.display_name,
        state=WindowsProfileState.PROVISIONING,
        windows_version=body.windows_version,
        architecture=body.architecture,
        vcpus=body.vcpus,
        ram_mb=body.ram_mb,
        disk_gb=body.disk_gb,
        user_profile=body.user_profile.model_dump(mode="json"),
        analysis_profile=body.analysis_profile,
        cape_template=body.cape_template,
        is_default=body.is_default,
        created_by_user_id=principal.user.id,
    )
    db.add(profile)
    await db.flush()
    operation = WindowsProfileOperation(
        profile_id=profile.id,
        operation_type=WindowsProfileOperationType.CREATE,
        state=WindowsProfileOperationState.QUEUED,
    )
    db.add(operation)
    await db.flush()
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="windows_profile.create_requested",
        target_type="windows_vm_profile",
        target_id=str(profile.id),
        payload={"operation_id": str(operation.id), "resources": profile.snapshot()},
    )
    await db.commit()
    return WindowsProfileActionResponse(profile=response(profile), operation_id=operation.id)


@router.delete(
    "/{profile_id}",
    response_model=WindowsProfileActionResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def delete_profile(
    profile_id: UUID,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> WindowsProfileActionResponse:
    profile = await db.get(WindowsVMProfile, profile_id, with_for_update=True)
    if not profile or profile.state in {WindowsProfileState.DELETED, WindowsProfileState.DELETING}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Windows profile not found")
    if profile.state == WindowsProfileState.PROVISIONING:
        raise HTTPException(status.HTTP_409_CONFLICT, "profile provisioning is still in progress")
    profile.state = WindowsProfileState.DELETING
    profile.retired_at = datetime.now(timezone.utc)
    profile.is_default = False
    operation = WindowsProfileOperation(
        profile_id=profile.id,
        operation_type=WindowsProfileOperationType.DELETE,
        state=WindowsProfileOperationState.QUEUED,
    )
    db.add(operation)
    await db.flush()
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="windows_profile.delete_requested",
        target_type="windows_vm_profile",
        target_id=str(profile.id),
        payload={"operation_id": str(operation.id)},
    )
    await db.commit()
    return WindowsProfileActionResponse(profile=response(profile), operation_id=operation.id)
