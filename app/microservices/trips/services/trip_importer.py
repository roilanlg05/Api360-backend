from __future__ import annotations

import logging
import re
from app.shared.models.trip import Trip
from datetime import datetime, date, time, timedelta
from typing import Any, BinaryIO, List, Optional

from openpyxl import load_workbook

logger = logging.getLogger(__name__)

# --- Regex para vuelos ---

# Vuelos tipo: WN 2453, AA1234, WN 2453-01, etc.
FLIGHT_ONLY_RE = re.compile(
    r"(?P<flight>[A-Z0-9]{2}\s*\d{3,4})(?:-\d{2})?"
)

# Vuelos + fecha opcional + hora:
# - "WN 2668-01 Nov 04:55"
# - "WN 4285-16 Nov 04:45"
# - también soporta sin mes: "WN 1322-01 17:20"
FLIGHT_TIME_RE = re.compile(
    r"(?P<flight>[A-Z0-9]{2}\s*\d{3,4}(?:-\d{2})?)\s+(?:[A-Za-z]{3}\s+)?(?P<hour>\d{1,2}):(?P<minute>\d{2})"
)

# ---------- Helpers básicos ----------

def find_city_code(ws) -> Optional[str]:
    """
    Busca en las primeras filas algo como:
    CITY:    SDF

    Devuelve el código de ciudad/airport (ej. 'SDF') o None si no lo encuentra.
    """
    max_rows_to_scan = 40  # más que suficiente para el header del schedule

    for row in ws.iter_rows(min_row=1, max_row=max_rows_to_scan):
        # Buscamos una celda que diga CITY o CITY:
        for cell in row:
            text = normalize_str(cell.value).upper()
            if not text:
                continue

            if text == "CITY" or text == "CITY:":
                # Encontramos la fila de CITY.
                # Ahora buscamos la siguiente celda no vacía en ESTA MISMA fila.
                row_idx = cell.row
                col_idx = cell.column

                # Miramos hacia la derecha
                for other_col in range(col_idx + 1, col_idx + 20):
                    other_cell = ws.cell(row=row_idx, column=other_col)
                    val = normalize_str(other_cell.value)
                    if val:
                        # Aquí debería venir 'SDF'
                        return val.upper()

                # Si no encontramos nada a la derecha, probamos cualquier
                # otra celda no vacía en la fila que NO sea CITY:
                values_in_row = [
                    normalize_str(c.value)
                    for c in row
                    if normalize_str(c.value) and normalize_str(c.value).upper() not in ("CITY", "CITY:")
                ]
                if values_in_row:
                    return values_in_row[0].upper()

    return None




def normalize_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def parse_service_date(value: Any) -> date:
    """
    Convierte la columna de fecha a date.
    Soporta date/datetime o strings tipo:
    "01-Nov-2025", "2025-11-01", "11/01/2025", etc.
    """
    if isinstance(value, date) and not isinstance(value, datetime):
        return value

    if isinstance(value, datetime):
        return value.date()

    text = normalize_str(value)
    if not text:
        raise ValueError("Fecha de servicio vacía")

    # Formatos típicos (incluyendo "01-Nov-2025")
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%d-%b-%Y", "%d-%B-%Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue

    raise ValueError(f"Formato de fecha no reconocido: {text!r}")


def parse_flight_only(value: str) -> Optional[str]:
    """
    Extrae vuelo tipo WN 2453-01 de un texto.
    Si no hay vuelo, devuelve None.
    """
    text = normalize_str(value)
    if not text:
        return None

    m = FLIGHT_ONLY_RE.search(text)
    if not m:
        return None

    return m.group("flight")


def parse_flight_and_time(value: str, service_date: date) -> tuple[Optional[str], Optional[datetime]]:
    """
    Extrae vuelo + hora de un texto tipo:
    - 'WN 2668-01 Nov 04:55'
    - 'WN 4285-16 Nov 04:45'
    - 'WN 1322-01 17:20'

    Si no encuentra patrón, devuelve (None, None).
    """
    text = normalize_str(value)
    if not text:
        return None, None

    m = FLIGHT_TIME_RE.search(text)
    if not m:
        return None, None

    flight = m.group("flight")
    hour = int(m.group("hour"))
    minute = int(m.group("minute"))

    dt = datetime(
        year=service_date.year,
        month=service_date.month,
        day=service_date.day,
        hour=hour,
        minute=minute,
    )

    return flight, dt


def split_airline_and_number(flight: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Separa 'WN 2453-01' en:
    - airline: 'WN'
    - flight_number: '2453-01'
    """
    if not flight:
        return None, None

    text = normalize_str(flight)
    m = re.match(r"^(?P<airline>[A-Z0-9]{2})\s*(?P<number>\d{1,4}(?:-\d{2})?)", text)
    if not m:
        # Si no matchea perfecto, devolvemos todo como número
        return None, text

    return m.group("airline"), m.group("number")


# ---------- Detección de encabezados ----------


def find_header_and_subheader(ws):
    """
    Busca la fila donde aparecen 'DATE', 'PICK UP', 'DROP OFF'
    y devuelve (row_index, header_row, subheader_row).
    """
    for row in ws.iter_rows(min_row=1, max_row=80):
        texts = [normalize_str(c.value).upper() for c in row if c.value is not None]
        if not texts:
            continue

        has_date = "DATE" in texts
        has_pickup = any("PICK" in t and "UP" in t for t in texts)
        has_dropoff = any("DROP" in t and "OFF" in t for t in texts)

        if has_date and has_pickup and has_dropoff:
            header_row_index = row[0].row
            header_row = row
            subheader_row = ws[header_row_index + 1]
            return header_row_index, header_row, subheader_row

    raise RuntimeError(
        "No se encontró la fila de encabezados (con DATE / PICK UP / DROP OFF) en la hoja Schedule."
    )


def determine_columns(header_row, subheader_row):
    """
    A partir de:
    - encabezado:  DATE | DEPARTMENT | #RIDERS | PICK UP | DROP OFF
    - subencabezado:  Location | From | Pickup Date/Time | Location | To

    Determina y devuelve un dict con:
    - date
    - riders
    - pickup_from
    - dropoff_to
    - pickup_location
    - dropoff_location
    """
    date_col = None
    riders_col = None

    # Encabezado principal
    for cell in header_row:
        text = normalize_str(cell.value).upper()
        if text == "DATE":
            date_col = cell.column
        if "RIDERS" in text:
            riders_col = cell.column

    if date_col is None:
        raise RuntimeError("No se encontró la columna DATE en el encabezado.")

    # Subencabezado
    pickup_loc_col = None
    dropoff_loc_col = None
    from_col = None
    to_col = None

    for cell in subheader_row:
        text = normalize_str(cell.value).upper()
        col = cell.column

        if text == "LOCATION":
            # Primer LOCATION = pickup, segundo LOCATION = dropoff
            if pickup_loc_col is None:
                pickup_loc_col = col
            else:
                dropoff_loc_col = col
        elif "FROM" in text:
            from_col = col
        elif text == "TO":
            to_col = col

    if from_col is None or to_col is None:
        raise RuntimeError("No se encontraron las columnas 'From' y 'To' en el subencabezado.")

    return {
        "date": date_col,
        "riders": riders_col,
        "pickup_from": from_col,
        "dropoff_to": to_col,
        "pickup_location": pickup_loc_col,
        "dropoff_location": dropoff_loc_col,
    }


# ---------- Import principal ----------


def load_trips_from_excel(stream: BinaryIO, sheet_name: str = "Schedule") -> list[Trip] | str:
    """
    Lee un Excel estilo Air Crew Transport / SDF y devuelve una lista de ImportedTrip,
    con la lógica:

    - Si 'From' (Pick Up) es vuelo (ej: 'WN 2623-01 Nov 11:15'):
        * pick_up_location = código aeropuerto (Location bajo PICK UP, ej. 'SDF')
        * drop_off_location = hotel (To bajo DROP OFF)
        * pick_up_time = hora del vuelo (si viene incluida en el texto)

    - Si 'From' (Pick Up) es hotel ('Hyatt Regency Louisville' / 'The Galt House'):
        * pick_up_location = hotel (From)
        * drop_off_location = aeropuerto (Location bajo DROP OFF, ej. 'SDF')
        * 'To' (DROP OFF) debe tener 'WN 2668-01 Nov 04:55'
        * pick_up_time = (hora de 'To') - 20 minutos
    """
    wb = load_workbook(stream, data_only=True)
    if sheet_name not in wb.sheetnames:
        raise RuntimeError(f"No se encontró la hoja {sheet_name!r} en el archivo de Excel.")

    ws = wb[sheet_name]

    city_code = find_city_code(ws)

    header_row_index, header_row, subheader_row = find_header_and_subheader(ws)
    cols = determine_columns(header_row, subheader_row)

    trips: List[Trip] = []
    current_service_date: Optional[date] = None

    # Datos empiezan después del subencabezado
    for row in ws.iter_rows(min_row=header_row_index + 2):
        row_idx = row[0].row

        def get(col_name: str):
            col_idx = cols.get(col_name)
            if not col_idx:
                return None
            return ws.cell(row=row_idx, column=col_idx).value

        # --- DATE con arrastre (heredamos la última fecha no vacía) ---
        date_raw = get("date")
        date_str = normalize_str(date_raw)

        # Cortar cuando llegamos a los textos finales del schedule
        upper_date_str = date_str.upper()
        if upper_date_str and (
            "END OF TRANSPORTATION SCHEDULE" in upper_date_str
            or "THIS SCHEDULE REPRESENTS" in upper_date_str
        ):
            # Terminamos el procesamiento; lo que sigue ya no son filas de viajes
            break

        if date_str:
            # Nueva fecha explícita
            try:
                service_date = parse_service_date(date_raw)
                current_service_date = service_date
            except Exception as exc:
                logger.error(
                    "Error parseando fecha en fila %s: %s",
                    row_idx,
                    exc,
                )
                # No podemos procesar esta fila sin fecha válida
                continue
        else:
            # Celda DATE vacía → usamos la última fecha válida
            if current_service_date is None:
                # Estamos antes de encontrar la primera fecha real → saltamos
                continue
            service_date = current_service_date

        # --- Otras columnas ---
        pickup_val = get("pickup_from")       # texto bajo 'From' en PICK UP
        dropoff_val = get("dropoff_to")       # texto bajo 'To' en DROP OFF
        pickup_loc_val = get("pickup_location")   # LOCATION (pickup)
        dropoff_loc_val = get("dropoff_location") # LOCATION (dropoff)
        riders_val = get("riders")

        pickup_raw = normalize_str(pickup_val)
        dropoff_raw = normalize_str(dropoff_val)

        # Fila totalmente vacía → la saltamos
        if not any([pickup_raw, dropoff_raw, pickup_loc_val, dropoff_loc_val]):
            continue

        try:
            # Determinamos código de aeropuerto (ej. SDF) a partir de las columnas Location
            airport_code: Optional[str] = None
            for v in (pickup_loc_val, dropoff_loc_val):
                s = normalize_str(v).upper()
                # Heurística simple: 3 letras mayúsculas → probablemente un airport code
                if len(s) == 3 and s.isalpha():
                    airport_code = s
                    break

            # Riders
            riders = 0
            if riders_val not in (None, ""):
                try:
                    riders = int(float(str(riders_val).strip()))
                except ValueError:
                    logger.warning(
                        "No se pudo convertir riders=%r a int en fila %s, se usará 0",
                        riders_val,
                        row_idx,
                    )
                    riders = 0

            # 1) ¿Pick Up (From) es un vuelo? (ej: 'WN 2623-01 Nov 11:15')
            flight_from_pickup = parse_flight_only(pickup_raw)

            if flight_from_pickup:
                # ----- Caso: PICK UP EN AEROPUERTO -----
                airline, flight_number = split_airline_and_number(flight_from_pickup)

                # pick_up_location será el código de aeropuerto, no 'WN 2623-01 ...'
                pick_up_location = airport_code or "AIRPORT"

                # Drop off:
                # - Si 'To' parece vuelo, también aeropuerto
                # - Si no, texto (hotel)
                dropoff_flight = parse_flight_only(dropoff_raw)
                if dropoff_flight and airport_code:
                    drop_off_location = airport_code
                else:
                    drop_off_location = dropoff_raw or (airport_code or "AIRPORT")

                # Horarios: intentamos sacar hora de To (dropoff) o From (pickup)
                _, dropoff_dt = parse_flight_and_time(dropoff_raw, service_date)
                if dropoff_dt is None:
                    _, pickup_dt = parse_flight_and_time(pickup_raw, service_date)
                else:
                    pickup_dt = dropoff_dt

                # Si no hay hora en ninguna parte, lo dejamos a las 00:00
                if pickup_dt is None:
                    pickup_dt = datetime(
                        year=service_date.year,
                        month=service_date.month,
                        day=service_date.day,
                        hour=0,
                        minute=0,
                    )

                pick_up_date = pickup_dt.date()
                pick_up_time = pickup_dt.time()

            else:
                # ----- Caso: PICK UP EN HOTEL -----
                pick_up_location = pickup_raw  # 'Hyatt Regency Louisville' / 'The Galt House'

                # 'To' (DROP OFF) debe tener vuelo + hora: 'WN 2668-01 Nov 04:55'
                flight_from_dropoff, dropoff_dt = parse_flight_and_time(dropoff_raw, service_date)
                if not flight_from_dropoff or not dropoff_dt:
                    raise ValueError(f"Formato inválido de vuelo en Drop Off: {dropoff_raw!r}")

                airline, flight_number = split_airline_and_number(flight_from_dropoff)

                # pick_up_time = hora del vuelo - 20 minutos
                pickup_dt = dropoff_dt - timedelta(minutes=20)
                pick_up_date = pickup_dt.date()
                pick_up_time = pickup_dt.time()

                # Drop off es en el aeropuerto
                drop_off_location = airport_code or "AIRPORT"

            trips.append(
                Trip(
                    pick_up_date=pick_up_date,
                    pick_up_time=pick_up_time,
                    pick_up_location=pick_up_location,
                    drop_off_location=drop_off_location,
                    airlane=airlane,
                    flight_number=flight_number,
                    riders=riders
                )
            )

        except Exception as exc:
            logger.error("Error parseando fila en hoja 'Schedule': %s", exc)
            # No paramos todo el proceso por una fila mala
            continue

    return trips, city_code
