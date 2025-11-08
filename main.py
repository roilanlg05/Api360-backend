from fastapi import FastAPI, Depends, HTTPException, status
from app.endpoints.auth import router as auth_router
from app.endpoints.drivers import router as drivers_router

app = FastAPI(title="Api360")

app.include_router(auth_router)
app.include_router(drivers_router)

@app.get("/", tags="Root")
async def get_root():
    
    return {
        "message": "Welcome to Api360"
    }
    
    