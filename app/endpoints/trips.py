from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Depends
from sqlalchemy import func
from sqlmodel import select
from app.core.db_session import SessionDep
from app.schemas.schemas import Trip as TripDB, Location, Airport
from app.services.trip_importer import load_trips_from_excel, Trip
from app.services.utils import AuthHelpers

router = APIRouter(prefix="/v1/trips", tags=["trips"])

auth = AuthHelpers()

@router.post("/upload-trips")
async def upload_trips(
    *,
    db: SessionDep,
    file: UploadFile = File(...), 
    role = Depends(auth.verify_role("manager"))
) -> dict:
    # Validar extensión del archivo
    if not (file.filename.endswith(".xlsx") or file.filename.endswith(".xlsm")):
        raise HTTPException(
            status_code=400,
            detail="Debe subir un archivo Excel (.xlsx / .xlsm).",
        )

    # Cargar viajes desde el Excel
    trips_import: list[Trip]
    aeroport_code: str
    trips_import, aeroport_code = load_trips_from_excel(stream=file.file)

    if not trips_import:
        raise HTTPException(
            status_code=400,
            detail="No se pudieron extraer viajes del archivo. Verifica que sea una hoja tipo 'Schedule'.",
        )
    
    
    airport = db.exec(select(Airport.longitude, Airport.latitude).where(Airport.code == aeroport_code)).one()
    # Location (por ahora fija a SDF, como lo tienes)
    location = Location(
        organization_id="43eca8f3-8e1b-48dc-a161-dd1024a0a543",
        name=aeroport_code,
        point={"type": "Point", "coordinates": [airport.longitude, airport.latitude]},
    )

    db.add(location)
    db.commit()
    db.refresh(location)

    created = 0

    for t in trips_import:
        db_trip = TripDB(
            location_id=location.id,
            pick_up_date=t.pick_up_date,
            pick_up_time=t.pick_up_time,
            pick_up_location=t.pick_up_location,
            drop_off_location=t.drop_off_location,
            aeroline=t.aeroline,
            flight_number=t.flight_number,
            riders=t.riders,
        )
        db.add(db_trip)
        created += 1

    db.commit()

    return {
        "status": "ok",
        "uploaded_rows": created,
        "location_id": str(location.id),
    }

@router.get("/")
async def get_trips(
    db: SessionDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    total = db.exec(select(func.count(TripDB.id))).one()
    trips = db.exec(
        select(TripDB)
        .order_by(
            TripDB.pick_up_date.asc(),
            TripDB.pick_up_time.asc(),
            TripDB.id.asc(),  # desempate estable
        )
        .offset(skip)
        .limit(limit)
    ).all()
    return {"data": trips, "skip": skip, "limit": limit, "total": total}