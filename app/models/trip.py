from pydantic import BaseModel
from datetime import date, time

class Trip(BaseModel):
    pick_up_date: date
    pick_up_time: time
    pick_up_location: str
    drop_off_location: str
    aeroline: str
    flight_number: str
    riders: int
    location_id: str | None = None

