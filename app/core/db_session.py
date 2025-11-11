from typing import Annotated, Generator
from fastapi import Depends
from sqlmodel import Session
from.db_config import engine

def get_db() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_db)]