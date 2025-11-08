from fastapi import APIRouter, Depends, HTTPException, status, Response
from app.models.user import CreateUser, UserSignIn, UpdateUser
from app.services.auth import set_cookies, delete_cookies, verify_token
from app.core.supabase_config import supabase

router = APIRouter(prefix="/v1/auth", tags=["Auth"])

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def registre_user(user: CreateUser) -> dict:

    payload = {
        "email": user.email,
        "password": user.password,
        "options": {
            "data": {
                "phone": user.phone,
                "role": user.role
            }
        }
    }
    try:
        resp = supabase.auth.sign_up(payload)
        return {"message": f"User created succesfully with id: {resp.user.id}"}
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Algo salio mal")
    
@router.post("/sign-in")
async def sign_in(user: UserSignIn, response: Response) -> dict:

    payload = {
            "email": user.email,
            "password": user.password,
        }
    
    #Try para manejar ecepciones si algo sale mal al trarar de registrarse
    
    try:
        resp = supabase.auth.sign_in_with_password(payload)
        json_resp = resp.session.model_dump()
        data = {
                "refresh_token": json_resp["refresh_token"],
                "expires_in": json_resp["expires_in"],
                "expires_at": json_resp["expires_at"],
            }
        set_cookies(response, data)
        return {"data": json_resp["access_token"]}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{e}")

@router.post("/refresh")
async def refresh_token(refresh_token: str):
    pass

@router.post("/sign-out")
async def sign_out(response: Response):
    cookie_list = ["refresh_token", "expires_in", "expires_at"]
    resp = supabase.auth.sign_out()
    delete_cookies(response, cookie_list)
    return resp

@router.put("/reset-password")
async def reset_password(user: UpdateUser, user_data: str = Depends(verify_token)):
    if user.email != user_data["email"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not Authorized or not authenticadted")
    
    response = supabase.auth.update_user(
        {"password": user.password}
    )
    return response