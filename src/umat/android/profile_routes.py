from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from umat.android.schemas import (
    AndroidProfileResponse,
    CreateAndroidProfileRequest,
    QualifyAndroidProfileRequest,
)
from umat.audit import append_audit
from umat.auth.dependencies import Principal, current_principal, require_roles
from umat.db import get_db
from umat.db.models import (
    AnalysisRun,
    AndroidAnalysisProfile,
    AndroidProfileState,
    AndroidRunConfiguration,
    Platform,
    RunResult,
    RunStatus,
)

router = APIRouter(prefix="/api/v1/android/profiles", tags=["android-profiles"])


def response(profile: AndroidAnalysisProfile) -> AndroidProfileResponse:
    return AndroidProfileResponse(
        id=profile.id,
        name=profile.name,
        display_name=profile.display_name,
        state=profile.state.value,
        android_version=profile.android_version,
        api_level=profile.api_level,
        architecture=profile.architecture,
        system_image=profile.system_image,
        emulator_version=profile.emulator_version,
        vcpus=profile.vcpus,
        ram_mb=profile.ram_mb,
        writable_system=profile.writable_system,
        network_mode=profile.network_mode,
        interaction_profile=profile.interaction_profile,
        is_default=profile.is_default,
        qualification=profile.qualification,
        created_at=profile.created_at,
        retired_at=profile.retired_at,
    )


@router.get("", response_model=list[AndroidProfileResponse])
async def list_profiles(
    include_inactive: bool = Query(False),
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> list[AndroidProfileResponse]:
    query = select(AndroidAnalysisProfile).order_by(AndroidAnalysisProfile.name)
    if "administrator" not in principal.roles or not include_inactive:
        query = query.where(AndroidAnalysisProfile.state == AndroidProfileState.ACTIVE)
    return [response(item) for item in (await db.scalars(query)).all()]


@router.post("", response_model=AndroidProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_profile(
    body: CreateAndroidProfileRequest,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> AndroidProfileResponse:
    if await db.scalar(
        select(AndroidAnalysisProfile).where(AndroidAnalysisProfile.name == body.name)
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "profile name already exists")
    if body.is_default:
        await db.execute(update(AndroidAnalysisProfile).values(is_default=False))
    profile = AndroidAnalysisProfile(
        **body.model_dump(),
        state=AndroidProfileState.ACTIVE,
        qualification={"status": "candidate", "dynamic_analysis": False},
        created_by_user_id=principal.user.id,
    )
    db.add(profile)
    await db.flush()
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="android_profile.created",
        target_type="android_analysis_profile",
        target_id=str(profile.id),
        payload={"resources": profile.snapshot()},
    )
    await db.commit()
    return response(profile)


@router.delete("/{profile_id}", response_model=AndroidProfileResponse)
async def retire_profile(
    profile_id: UUID,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> AndroidProfileResponse:
    profile = await db.get(AndroidAnalysisProfile, profile_id, with_for_update=True)
    if not profile or profile.state == AndroidProfileState.RETIRED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android profile not found")
    if profile.is_default:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "select another default profile before retiring this one"
        )
    profile.state = AndroidProfileState.RETIRED
    profile.is_default = False
    profile.retired_at = datetime.now(timezone.utc)
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="android_profile.retired",
        target_type="android_analysis_profile",
        target_id=str(profile.id),
        payload={},
    )
    await db.commit()
    return response(profile)


@router.post("/{profile_id}/qualify", response_model=AndroidProfileResponse)
async def qualify_profile(
    profile_id: UUID,
    body: QualifyAndroidProfileRequest,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> AndroidProfileResponse:
    profile = await db.get(AndroidAnalysisProfile, profile_id, with_for_update=True)
    run = await db.get(AnalysisRun, body.evidence_run_id)
    configuration = await db.get(AndroidRunConfiguration, body.evidence_run_id)
    if not profile or profile.state != AndroidProfileState.ACTIVE:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "active Android profile not found")
    if (
        not run
        or not configuration
        or configuration.profile_id != profile.id
        or run.platform != Platform.ANDROID
        or run.status != RunStatus.TERMINAL
        or run.result != RunResult.COMPLETED
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "qualification requires a completed run using this profile",
        )
    profile.qualification = {
        "status": "qualified",
        "dynamic_analysis": True,
        "evidence_run_id": str(run.id),
        "qualified_at": datetime.now(timezone.utc).isoformat(),
    }
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="android_profile.qualified",
        target_type="android_analysis_profile",
        target_id=str(profile.id),
        payload={"evidence_run_id": str(run.id)},
    )
    await db.commit()
    return response(profile)
