from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Request, Response
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import bcrypt
import jwt
import secrets
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel
from typing import List, Optional, Any
from bson import ObjectId

# MongoDB
mongo_url = os.environ['MONGO_URL']
db_name = os.environ['DB_NAME']
client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# JWT
JWT_SECRET = os.environ.get('JWT_SECRET', 'change-this-secret')
JWT_ALGORITHM = 'HS256'

app = FastAPI(title='SurgiLog API')
api_router = APIRouter(prefix='/api')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=False,
    allow_methods=['*'],
    allow_headers=['*'],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- Auth Helpers ---
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))


def create_access_token(user_id: str, email: str) -> str:
    payload = {
        'sub': user_id,
        'email': email,
        'exp': datetime.now(timezone.utc) + timedelta(days=30),
        'type': 'access'
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get('access_token')
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get('type') != 'access':
            raise HTTPException(status_code=401, detail='Invalid token type')
        user = await db.users.find_one({'_id': ObjectId(payload['sub'])})
        if not user:
            raise HTTPException(status_code=401, detail='User not found')
        user['_id'] = str(user['_id'])
        user.pop('password_hash', None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid token')


def serialize_doc(doc: dict) -> dict:
    doc['_id'] = str(doc['_id'])
    for key in ['created_at', 'updated_at']:
        if isinstance(doc.get(key), datetime):
            doc[key] = doc[key].isoformat()
    return doc


# --- Pydantic Models ---
class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class CaseImage(BaseModel):
    uri: str
    category: str


class CaseLogCreate(BaseModel):
    # Section A
    mrd_ip_number: str = ''
    age: str = ''
    sex: str = ''
    place: str = ''
    hospital_name: str = ''
    setup_type: str = ''
    # Section B
    provisional_diagnosis: str = ''
    case_summary: str = ''
    preop_diagnosis: str = ''
    postop_diagnosis: str = ''
    findings: str = ''
    # Section C
    surgery_date: str = ''
    surgery_time: str = ''
    department: str = ''
    unit: str = ''
    unit_chief: str = ''
    operating_surgeons: str = ''
    user_role: str = ''
    case_type: str = ''
    # Section D
    procedure_name: str = ''
    duration_hours: str = ''
    duration_minutes: str = ''
    anaesthesia_type: str = ''
    operative_steps: str = ''
    intraop_findings: str = ''
    modifications: str = ''
    # Section E
    discharge_date: str = ''
    hospital_stay_days: str = ''
    complications: str = ''
    reintervention: bool = False
    reintervention_details: str = ''
    histopathology: str = ''
    postop_investigations: str = ''
    # Section F
    tag_thesis: bool = False
    tag_research: bool = False
    tag_emergency: bool = False
    tag_interesting: bool = False
    tag_rare: bool = False
    # Section G
    images: List[CaseImage] = []
    # Section H
    remarks: str = ''


class CaseLogUpdate(CaseLogCreate):
    pass


# --- Auth Endpoints ---
@api_router.post('/auth/register')
async def register(body: UserRegister, response: Response):
    email = body.email.lower().strip()
    username = body.username.strip()
    if not username or not email or not body.password:
        raise HTTPException(status_code=400, detail='All fields are required')
    existing = await db.users.find_one({'$or': [{'email': email}, {'username': username}]})
    if existing:
        if existing.get('email') == email:
            raise HTTPException(status_code=400, detail='Email already registered')
        raise HTTPException(status_code=400, detail='Username already taken')
    user_doc = {
        'username': username,
        'email': email,
        'password_hash': hash_password(body.password),
        'created_at': datetime.now(timezone.utc),
        'role': 'user'
    }
    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)
    token = create_access_token(user_id, email)
    response.set_cookie(key='access_token', value=token, httponly=True, secure=False, samesite='lax', max_age=2592000, path='/')
    return {'id': user_id, 'username': username, 'email': email, 'role': 'user', 'access_token': token, 'token_type': 'bearer'}


@api_router.post('/auth/login')
async def login(body: UserLogin, response: Response):
    email_or_user = body.email.strip()
    user = await db.users.find_one({'$or': [{'email': email_or_user.lower()}, {'username': email_or_user}]})
    if not user or not verify_password(body.password, user['password_hash']):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    user_id = str(user['_id'])
    token = create_access_token(user_id, user['email'])
    response.set_cookie(key='access_token', value=token, httponly=True, secure=False, samesite='lax', max_age=2592000, path='/')
    return {'id': user_id, 'username': user.get('username', ''), 'email': user['email'], 'role': user.get('role', 'user'), 'access_token': token, 'token_type': 'bearer'}


@api_router.post('/auth/logout')
async def logout(response: Response):
    response.delete_cookie('access_token', path='/')
    return {'message': 'Logged out'}


@api_router.get('/auth/me')
async def get_me(request: Request):
    return await get_current_user(request)


@api_router.post('/auth/forgot-password')
async def forgot_password(body: ForgotPasswordRequest):
    email = body.email.lower().strip()
    user = await db.users.find_one({'email': email})
    if user:
        token = secrets.token_urlsafe(32)
        await db.password_reset_tokens.insert_one({
            'token': token, 'user_id': str(user['_id']), 'email': email,
            'created_at': datetime.now(timezone.utc),
            'expires_at': datetime.now(timezone.utc) + timedelta(hours=1),
            'used': False
        })
        logger.info(f'Password reset token for {email}: {token}')
    return {'message': 'If this email is registered, a reset link has been sent.'}


@api_router.post('/auth/reset-password')
async def reset_password(body: ResetPasswordRequest):
    doc = await db.password_reset_tokens.find_one({'token': body.token, 'used': False, 'expires_at': {'$gt': datetime.now(timezone.utc)}})
    if not doc:
        raise HTTPException(status_code=400, detail='Invalid or expired reset token')
    await db.users.update_one({'_id': ObjectId(doc['user_id'])}, {'$set': {'password_hash': hash_password(body.new_password)}})
    await db.password_reset_tokens.update_one({'_id': doc['_id']}, {'$set': {'used': True}})
    return {'message': 'Password reset successfully'}


# --- Case Endpoints ---
def generate_case_id() -> str:
    import random, string
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f'SL-{datetime.now(timezone.utc).year}-{suffix}'


@api_router.post('/cases')
async def create_case(body: CaseLogCreate, request: Request):
    user = await get_current_user(request)
    case_doc = body.model_dump()
    case_doc['images'] = [img.model_dump() for img in body.images]
    case_doc['case_id'] = generate_case_id()
    case_doc['user_id'] = user['_id']
    case_doc['created_at'] = datetime.now(timezone.utc)
    case_doc['updated_at'] = datetime.now(timezone.utc)
    result = await db.cases.insert_one(case_doc)
    case_doc['_id'] = str(result.inserted_id)
    case_doc['created_at'] = case_doc['created_at'].isoformat()
    case_doc['updated_at'] = case_doc['updated_at'].isoformat()
    return case_doc


@api_router.get('/cases/stats')
async def get_stats(request: Request):
    user = await get_current_user(request)
    all_cases = await db.cases.find({'user_id': user['_id']}).to_list(10000)
    total = len(all_cases)
    major = sum(1 for c in all_cases if c.get('case_type', '').lower() == 'major')
    minor = sum(1 for c in all_cases if c.get('case_type', '').lower() == 'minor')
    emergency = sum(1 for c in all_cases if c.get('tag_emergency', False))
    elective = total - emergency
    research = sum(1 for c in all_cases if c.get('tag_research', False) or c.get('tag_thesis', False))
    now = datetime.now(timezone.utc)
    from collections import defaultdict
    weekly = defaultdict(int)
    monthly = defaultdict(int)
    yearly = defaultdict(int)
    for case in all_cases:
        ca = case.get('created_at')
        if isinstance(ca, datetime):
            if ca.tzinfo is None:
                ca = ca.replace(tzinfo=timezone.utc)
            diff = (now - ca).days
            if diff < 7:
                weekly[ca.strftime('%a')] += 1
            if diff < 30:
                week_num = diff // 7
                monthly[f'W{week_num + 1}'] += 1
            if ca.year == now.year:
                yearly[ca.strftime('%b')] += 1
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    weeks = ['W1', 'W2', 'W3', 'W4']
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    return {
        'total': total, 'major': major, 'minor': minor,
        'emergency': emergency, 'elective': elective, 'research': research,
        'weekly': [{'label': d, 'count': weekly.get(d, 0)} for d in days],
        'monthly': [{'label': w, 'count': monthly.get(w, 0)} for w in weeks],
        'yearly': [{'label': m, 'count': yearly.get(m, 0)} for m in months]
    }


@api_router.get('/cases')
async def get_cases(request: Request):
    user = await get_current_user(request)
    cases = await db.cases.find({'user_id': user['_id']}).sort('created_at', -1).to_list(1000)
    return [serialize_doc(c) for c in cases]


@api_router.get('/cases/{case_id}')
async def get_case(case_id: str, request: Request):
    user = await get_current_user(request)
    try:
        case = await db.cases.find_one({'_id': ObjectId(case_id), 'user_id': user['_id']})
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid case ID')
    if not case:
        raise HTTPException(status_code=404, detail='Case not found')
    return serialize_doc(case)


@api_router.put('/cases/{case_id}')
async def update_case(case_id: str, body: CaseLogUpdate, request: Request):
    user = await get_current_user(request)
    try:
        existing = await db.cases.find_one({'_id': ObjectId(case_id), 'user_id': user['_id']})
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid case ID')
    if not existing:
        raise HTTPException(status_code=404, detail='Case not found')
    update_data = body.model_dump()
    update_data['images'] = [img.model_dump() for img in body.images]
    update_data['updated_at'] = datetime.now(timezone.utc)
    await db.cases.update_one({'_id': ObjectId(case_id)}, {'$set': update_data})
    updated = await db.cases.find_one({'_id': ObjectId(case_id)})
    return serialize_doc(updated)


@api_router.delete('/cases/{case_id}')
async def delete_case(case_id: str, request: Request):
    user = await get_current_user(request)
    try:
        result = await db.cases.delete_one({'_id': ObjectId(case_id), 'user_id': user['_id']})
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid case ID')
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail='Case not found')
    return {'message': 'Case deleted'}


# --- Profile Endpoints ---
class UserProfileUpdate(BaseModel):
    full_name: str = ''
    date_of_birth: str = ''
    training_level: str = ''
    specialty: str = ''


@api_router.get('/profile')
async def get_profile(request: Request):
    user = await get_current_user(request)
    return {
        'full_name': user.get('full_name', ''),
        'date_of_birth': user.get('date_of_birth', ''),
        'training_level': user.get('training_level', ''),
        'specialty': user.get('specialty', ''),
    }


@api_router.put('/profile')
async def update_profile(body: UserProfileUpdate, request: Request):
    user = await get_current_user(request)
    await db.users.update_one(
        {'_id': ObjectId(user['_id'])},
        {'$set': body.model_dump()}
    )
    return {'message': 'Profile updated', **body.model_dump()}


@api_router.get('/suggestions')
async def get_suggestions(request: Request):
    user = await get_current_user(request)
    cases = await db.cases.find(
        {'user_id': user['_id']},
        {'hospital_name': 1, 'operating_surgeons': 1, 'department': 1, 'unit': 1, 'unit_chief': 1}
    ).to_list(1000)

    def unique_vals(field: str) -> list:
        vals = set()
        for c in cases:
            v = c.get(field, '')
            if v and str(v).strip():
                vals.add(str(v).strip())
        return sorted(vals)[:20]

    return {
        'hospital_name': unique_vals('hospital_name'),
        'operating_surgeons': unique_vals('operating_surgeons'),
        'department': unique_vals('department'),
        'unit': unique_vals('unit'),
        'unit_chief': unique_vals('unit_chief'),
    }


app.include_router(api_router)


@app.on_event('startup')
async def startup():
    await db.users.create_index('email', unique=True)
    await db.users.create_index('username', unique=True)
    try:
        await db.password_reset_tokens.create_index('expires_at', expireAfterSeconds=0)
    except Exception:
        pass
    await db.cases.create_index([('user_id', 1), ('created_at', -1)])
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@surgilog.com')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123!')
    existing = await db.users.find_one({'email': admin_email})
    if not existing:
        await db.users.insert_one({'username': 'admin', 'email': admin_email, 'password_hash': hash_password(admin_password), 'role': 'admin', 'created_at': datetime.now(timezone.utc)})
        logger.info(f'Admin seeded: {admin_email}')
    elif not verify_password(admin_password, existing['password_hash']):
        await db.users.update_one({'email': admin_email}, {'$set': {'password_hash': hash_password(admin_password)}})
    creds = Path('/app/memory/test_credentials.md')
    creds.parent.mkdir(exist_ok=True)
    creds.write_text(f"""# SurgiLog Test Credentials

## Admin User
- Email: {admin_email}
- Password: {admin_password}
- Role: admin

## Auth Endpoints
- POST /api/auth/register
- POST /api/auth/login
- POST /api/auth/logout
- GET /api/auth/me
- POST /api/auth/forgot-password

## Case Endpoints
- GET /api/cases
- POST /api/cases
- GET /api/cases/stats
- GET /api/cases/:id
- PUT /api/cases/:id
- DELETE /api/cases/:id
""")


@app.on_event('shutdown')
async def shutdown():
    client.close()
