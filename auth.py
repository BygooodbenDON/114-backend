from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

fake_users_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

# JWT 設定
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7  # ### 新增：Refresh Token 效期通常較長 (例如 7 天)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ### 修改：將製作 Token 的邏輯通用化，或保留原本的再多寫一個
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"}) # 建議加入 type 區分
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ### 新增：製作 Refresh Token 的函數
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire, "type": "refresh"}) # 標記這是 refresh token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 驗證 Token (Access Token 用)
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if username is None or token_type != "access": # 確保不能拿 Refresh Token 當 Access Token 用
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # ### 修改：同時產生 Access Token 和 Refresh Token
    access_token = create_access_token(data={"sub": user["username"]})
    refresh_token = create_refresh_token(data={"sub": user["username"]})

    # 設定 Access Token Cookie (短效)
    response.set_cookie(
        key="access_token", # 建議改名區分，原本叫 jwt
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    # ### 新增：設定 Refresh Token Cookie (長效，務必 HttpOnly)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True, 
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )

    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }

# ### 新增： Refresh Endpoint
@app.post("/refresh")
def refresh(response: Response, refresh_token: Optional[str] = Cookie(None)):
    """
    使用 Refresh Token 換取新的 Access Token
    """
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    try:
        # 1. 解碼 Refresh Token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")

        # 2. 檢查這是否真的是一個 Refresh Token
        if token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        # (選用步驟) 在真實資料庫中，這裡應該檢查該 User 是否還存在，或者 Refresh Token 是否被列入黑名單

        # 3. 發放新的 Access Token
        new_access_token = create_access_token(data={"sub": username})

        # 4. 更新使用者的 Cookie
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            samesite="lax",
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

        return {"access_token": new_access_token, "token_type": "bearer"}

    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

@app.get("/protected")
def protected(token: Optional[str] = Depends(oauth2_scheme), access_token: Optional[str] = Cookie(None)):
    # 這裡參數名改為 access_token 對應 login 設定的 cookie key
    if token:
        username = verify_token(token)
    elif access_token:
        username = verify_token(access_token)
    else:
        raise HTTPException(status_code=401, detail="Missing access token")

    return {"message": f"Hello, {username}! You are authenticated."}