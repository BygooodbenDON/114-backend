from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from oauth_google import verify_google_id_token
from .auth_utils import create_access_token, get_current_user_email

app = FastAPI(title="資工系 114-Backend 示範專案")

# 定義前端傳入的資料格式
class TokenRequest(BaseModel):
    id_token: str

# 1. Google 登入換取自家 JWT 的接口
@app.post("/auth/google", summary="Google OAuth 登入驗證")
async def google_auth(request: TokenRequest):
    """
    接收前端拿到的 Google id_token，驗證後發放本系統的 JWT
    """
    # Step A: 呼叫 google_oauth.py 驗證身分
    user_info = verify_google_id_token(request.id_token)
    
    # Step B: 取得使用者 email (通常作為 User Unique ID)
    user_email = user_info.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="Google 帳號未提供 Email")

    # Step C: (可選) 在此處檢查資料庫，若無此使用者則新增
    # user = db.query(User).filter(User.email == user_email).first()
    
    # Step D: 呼叫 auth_utils.py 簽發自家的 Access Token
    access_token = create_access_token(data={"sub": user_email})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "name": user_info.get("name"),
            "email": user_email,
            "picture": user_info.get("picture")
        }
    }

# 2. 受保護的路由 (需要 JWT 才能進入)
@app.get("/users/me", summary="取得當前使用者資訊")
async def read_users_me(current_user: str = Depends(get_current_user_email)):
    """
    只有在 Header 帶上有效的 Authorization: Bearer <JWT> 才能存取
    """
    return {
        "msg": "成功通過 JWT 驗證",
        "user_email": current_user
    }

# 3. 測試用公開路由
@app.get("/")
def root():
    return {"message": "Hello FastAPI OAuth Demo"}