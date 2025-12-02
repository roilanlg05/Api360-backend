from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Depends
from sqlalchemy import func
from sqlmodel import select
from shared.database.db_settings import AsyncSessionDep
from shared.schemas.schemas import Trip as TripDB, Location, Airport
from services.trip_importer import load_trips_from_bytes, Trip
from services.utils import Auth

router = APIRouter(prefix="/v1/trips", tags=["trips"])

auth = Auth()


@router.post("/upload-trips")
async def upload_trips(
    *,
    session: AsyncSessionDep,
    file: UploadFile = File(...), 
    role = Depends(auth.verify_role(["manager"]))
) -> dict:
    """
    Sube un archivo Excel con el schedule de trips y los guarda en la base de datos.
    """
    # Validar extensión del archivo
    if not file.filename or not (file.filename.endswith(".xlsx") or file.filename.endswith(".xlsm")):
        raise HTTPException(
            status_code=400,
            detail="Debe subir un archivo Excel (.xlsx / .xlsm).",
        )

    # Leer el contenido del archivo
    content = await file.read()

    # Cargar viajes desde el Excel (función asíncrona)
    try:
        trips_import, airport_code = await load_trips_from_bytes(content)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not trips_import:
        raise HTTPException(
            status_code=400,
            detail="No se pudieron extraer viajes del archivo. Verifica que sea una hoja tipo 'Schedule'.",
        )

    if not airport_code:
        raise HTTPException(
            status_code=400,
            detail="No se pudo detectar el código del aeropuerto en el archivo.",
        )

    # Buscar el aeropuerto en la base de datos
    stmt = select(Airport).where(Airport.code == airport_code)
    result = await session.exec(stmt)
    airport = result.first()

    if not airport:
        raise HTTPException(
            status_code=404,
            detail=f"Aeropuerto con código '{airport_code}' no encontrado.",
        )

    # Crear Location
    location = Location(
        organization_id="43eca8f3-8e1b-48dc-a161-dd1024a0a543",  # TODO: obtener del usuario autenticado
        name=airport_code,
        point={"type": "Point", "coordinates": [airport.longitude, airport.latitude]},
    )

    session.add(location)
    await session.flush()
    await session.refresh(location)

    # Crear los trips
    created = 0
    for t in trips_import:
        db_trip = TripDB(
            location_id=location.id,
            pick_up_date=t.pick_up_date,
            pick_up_time=t.pick_up_time,
            pick_up_location=t.pick_up_location,
            drop_off_location=t.drop_off_location,
            airline=t.airline,
            flight_number=t.flight_number,
            riders=t.riders,
        )
        session.add(db_trip)
        created += 1

    await session.commit()

    return {
        "status": "ok",
        "uploaded_rows": created,
        "location_id": str(location.id),
        "airport_code": airport_code,
    }


@router.get("/")
async def get_trips(
    session: AsyncSessionDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    """
    Obtiene una lista paginada de trips.
    """
    # Contar total
    count_stmt = select(func.count(TripDB.id))
    total_result = await session.exec(count_stmt)
    total = total_result.one()

    # Obtener trips paginados
    trips_stmt = (
        select(TripDB)
        .order_by(
            TripDB.pick_up_date.asc(),
            TripDB.pick_up_time.asc(),
            TripDB.id.asc(),
        )
        .offset(skip)
        .limit(limit)
    )
    trips_result = await session.exec(trips_stmt)
    trips = trips_result.all()

    return {
        "data": trips, 
        "skip": skip, 
        "limit": limit, 
        "total": total
    }


@router.get("/{trip_id}")
async def get_trip(
    trip_id: str,
    session: AsyncSessionDep,
):
    """
    Obtiene un trip por su ID.
    """
    from uuid import UUID
    
    try:
        uuid_id = UUID(trip_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="ID de trip inválido")

    stmt = select(TripDB).where(TripDB.id == uuid_id)
    result = await session.exec(stmt)
    trip = result.first()

    if not trip:
        raise HTTPException(status_code=404, detail="Trip no encontrado")

    return trip