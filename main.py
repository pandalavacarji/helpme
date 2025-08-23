from fastapi import FastAPI
from fastapi_mqtt import FastMQTT, MQTTConfig
from pydantic import BaseModel

app = FastAPI()

# MQTT broker configuration (update to your actual broker!)
mqtt_config = MQTTConfig(
    host="test.mosquitto.org",  # Change to your MQTT broker here
    port=1883
)
fast_mqtt = FastMQTT(config=mqtt_config)
fast_mqtt.init_app(app)

class Card(BaseModel):
    CardIndex: int = 0
    Card: int
    TZ1: int = 1
    TZ2: int = 0
    Password: str = ""
    BeginTime: str = ""
    EndTime: str = ""
    Name: str = ""
    Status: int = 1

def command_topic(product_key: str, device_name: str):
    return f"/sys/{product_key}/{device_name}/thing/command/post"

@app.post("/open_turnstile/")
async def open_turnstile(product_key: str, device_name: str, door: int = 0):
    message = {
        "id": 2017,
        "taskNo": 10,
        "data": {
            "Door": door,
            "Open": 1
        },
        "version": "1.0",
        "method": "OpenDoor"
    }
    topic = command_topic(product_key, device_name)
    await fast_mqtt.publish(topic, str(message))
    return {"result": "sent", "topic": topic, "payload": message}

@app.post("/add_card/")
async def add_card(product_key: str, device_name: str, body: Card):
    message = {
        "id": 44,
        "taskNo": 10,
        "data": body.dict(),
        "version": "1.0",
        "method": "AddCard"
    }
    topic = command_topic(product_key, device_name)
    await fast_mqtt.publish(topic, str(message))
    return {"result": "sent", "topic": topic, "payload": message}

@app.post("/delete_card/")
async def delete_card(product_key: str, device_name: str, card: int):
    message = {
        "id": 64,
        "taskNo": 10,
        "data": {
            "Card": card
        },
        "version": "1.0",
        "method": "DeleteCard"
    }
    topic = command_topic(product_key, device_name)
    await fast_mqtt.publish(topic, str(message))
    return {"result": "sent", "topic": topic, "payload": message}

@app.get("/")
async def root():
    return {"message": "FastAPI Turnstile Controller is running!"}
