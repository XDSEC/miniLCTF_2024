"backend"

import os
from math import atan2, cos, radians, sin, sqrt
from random import sample
from time import time

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    "Return distance (unit: m)"
    earth_r = 6371_000.0

    lat1 = radians(lat1)
    lon1 = radians(lon1)
    lat2 = radians(lat2)
    lon2 = radians(lon2)

    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return earth_r * c


status = "ready" # must be one of ["ready", "running", "timeout", "cheating", "finished"]
distance_sum = 0
checkpoints = [{"label": "下北泽", "lat": 11.4, "lon": 51.4}]
location_records = [(191981.0, 11.4, 51.4)]
last_msg = "you have not start the game yet!"

def check_location(new_lat: float, new_lon: float):
    "Check and log location"
    global status, distance_sum, last_msg
    if status != "running":
        return last_msg
    new_ts = time()
    if len(location_records) < 1:
        location_records.append((new_ts, new_lat, new_lon))
        last_msg = "冲刺，冲!♿"
        return last_msg
    last_ts, last_lat, last_lon = location_records[-1]
    time_delta = new_ts - last_ts
    if time_delta > 10:
        status = "timeout"
        last_msg = "timeout! are you sleeping?"
        return last_msg
    if time_delta < 1:
        return "are you robot?"
    distance = calculate_distance(last_lat, last_lon, new_lat, new_lon)
    if distance > 100:
        status = "cheating"
        last_msg = f"move too long, are you teleporting? ({distance=})"
        return last_msg
    velocity = distance / time_delta
    if velocity > 40:
        status = "cheating"
        last_msg = f"move too fast, are you flying? ({velocity=}, {distance=}, {time_delta=})"
        return last_msg
    location_records.append((new_ts, new_lat, new_lon))
    distance_sum += distance
    for index, item in enumerate(checkpoints):
        if calculate_distance(new_lat, new_lon, item["lat"], item["lon"]) < 50:
            checkpoints.pop(index)
    if len(checkpoints) == 0 and status == "running" and distance_sum > 10 * 1000:
        first_ts = location_records[0][0]
        avg_velocity = distance_sum / (new_ts - first_ts)
        if avg_velocity > 10:
            status = "finished"
            last_msg = "congratulations! you have finished the game!"
            return last_msg
        else:
            return "you are too slow!"
    return "more more run!"


def restart():
    "Reset all stats"
    global checkpoints, distance_sum, status
    checkpoints = sample(
        [
            {"label": "A楼", "lon": 108.837184, "lat": 34.133179},
            {"label": "北门", "lon": 108.843728, "lat": 34.134961},
            {"label": "东门", "lon": 108.846755, "lat": 34.128226},
            {"label": "图书馆北侧", "lon": 108.839138, "lat": 34.131461},
            {"label": "丁香餐厅北侧", "lon": 108.836061, "lat": 34.130214},
            {"label": "网安大楼东侧", "lon": 108.836061, "lat": 34.130214},
            {"label": "竹园1号楼", "lon": 108.846993, "lat": 34.132899},
            {"label": "北操西侧入口", "lon": 108.846993, "lat": 34.132899},
        ],
        k=3,
    )
    location_records.clear()
    distance_sum = 0
    status = "running"


class StatusResponseModel(BaseModel):
    "Response Model `GET /status`"
    status: str
    distance: float
    flag: str


class LocationRequestModel(BaseModel):
    "Request Model `POST /location`"
    lat: float
    lon: float


class LocationResponseModel(BaseModel):
    "Response Model `POST /location`"
    status: str
    message: str


class CheckpointModel(BaseModel):
    "Part of `CheckpointsResponseModel`"
    label: str
    lat: float
    lon: float


class CheckpointsResponseModel(BaseModel):
    "Response Model `GET /checkpoint`"
    checkpoints: list[CheckpointModel]


app = FastAPI()


@app.get("/status")
def get_status() -> StatusResponseModel:
    'Get current status of the game. If the status is "finish", the flag will be returned.'
    flag = "flag{welcome_to_🤣🔪🙅🏃🏻_and_wish_you_enjoy_running!!!}"
    if status == "finished":
        flag = os.getenv("FLAG")
    return StatusResponseModel(status=status, distance=distance_sum, flag=flag)


@app.post("/location")
def post_location(loc: LocationRequestModel) -> LocationResponseModel:
    "Post current location."
    msg = check_location(loc.lat, loc.lon)
    return LocationResponseModel(status=status, message=msg)


@app.get("/checkpoints")
def get_checkpoints() -> CheckpointsResponseModel:
    "Get remaining checkpoints."
    return CheckpointsResponseModel(checkpoints=checkpoints)


@app.get("/restart")
def get_restart():
    "Restart game."
    restart()
    return "ok"


# @app.get("/")
# def get_redirect_to_app():
#     return RedirectResponse("/app/", status_code=301)

app.mount("/", StaticFiles(directory="./frontend", html=True), name="frontend")
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        workers=1,
    )
