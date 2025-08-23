from fastapi import FastAPI
from fastapi_mqtt import FastMQTT, MQTTConfig
import json

app = FastAPI()

# --- MQTT broker configuration ---
mqtt_config = MQTTConfig(
    host="test.mosquitto.org",  # Change this to your MQTT broker host
    port=1883
)
fast_mqtt = FastMQTT(config=mqtt_config)
fast_mqtt.init_app(app)
# ---------------------------------

@app.get("/")
async def root():
    return {"message": "FastAPI Turnstile Controller is running!"}

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
    fast_mqtt.publish(topic, json.dumps(message))  # No await here
    return {
        "result": "MQTT sent",
        "topic": topic,
        "payload": message
    }
