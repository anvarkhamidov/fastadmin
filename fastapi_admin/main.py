import logging
import os
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from fastapi_admin.api.api import router as api_router
from fastapi_admin.models.base import BaseModelAdmin
from fastapi_admin.settings import settings
from fastapi_admin.views import router as views_router

logger = logging.getLogger(__name__)

admin_app = FastAPI(
    openapi_url=False,
)
admin_models: dict[Any, type[BaseModelAdmin]] = {}

current_dir = os.path.dirname(os.path.abspath(__file__))
admin_app.mount(
    "/static",
    StaticFiles(directory=os.path.join(current_dir, "static")),
    name="static",
)
admin_app.include_router(api_router)
admin_app.include_router(views_router)

app = FastAPI()
app.mount(f"/{settings.ADMIN_PREFIX}", admin_app)
# CORS
origins = [
    "http://localhost:3030",
    "http://127.0.0.1:3030",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
