from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from google_oauth import verify_google_id_token, exchange_code_for_tokens
from auth_utils import create_access_token, get_current_user_email

app = FastAPI(title="資工系 114-Backend 示範專案")

# 定義前端傳入的資料格式
class TokenRequest(BaseModel):
    """[架構 B] 前端直接傳 id_token"""
    id_token: str


class CodeRequest(BaseModel):
    """[架構 A] 前端傳 authorization code，後端負責換 token"""
    code: str
    redirect_uri: str  # 必須與前端導向 Google 時使用的一致


# ============================================================
# 架構 A: Authorization Code Flow
# - 前端只傳 code，後端用 code + secret 換 token
# - 較安全，適合有後端的網站
# ============================================================
@app.post("/auth/google/code", summary="[架構A] 用 Code 換取 JWT")
async def google_auth_with_code(request: CodeRequest):
    """
    接收前端傳來的 authorization code，後端負責：
    1. 用 code + client_secret 向 Google 換取 tokens
    2. 驗證 id_token
    3. 發放自家 JWT
    """
    # Step 1: 用 code 換 tokens（這步需要 client_secret，只能在後端做！）
    tokens = exchange_code_for_tokens(request.code, request.redirect_uri)

    # Step 2: 從 tokens 中取出 id_token 並驗證
    google_id_token = tokens.get("id_token")
    if not google_id_token:
        raise HTTPException(status_code=400, detail="Google 未回傳 id_token")

    user_info = verify_google_id_token(google_id_token)

    # Step 3: 取得使用者資訊
    user_email = user_info.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="Google 帳號未提供 Email")

    # Step 4: 發放自家 JWT
    access_token = create_access_token(data={"sub": user_email})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "name": user_info.get("name"),
            "email": user_email,
            "picture": user_info.get("picture")
        },
        # 可選：也回傳 Google 的 tokens，讓前端可以呼叫 Google API
        "google_access_token": tokens.get("access_token"),
    }


# ============================================================
# 架構 B: Google Sign-In SDK Flow
# - 前端用 Google SDK 直接拿到 id_token
# - 較簡單，適合純前端應用或快速開發
# ============================================================
@app.post("/auth/google", summary="[架構B] 用 ID Token 換取 JWT")
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