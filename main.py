from fastapi import FastAPI
from fastapi_mqtt import FastMQTT, MQTTConfig
import json

app = FastAPI()

# --- Configure this to your MQTT broker ---
mqtt_config = MQTTConfig(
    host="test.mosquitto.org",  # Use your MQTT broker here if needed
    port=1883
)
fast_mqtt = FastMQTT(config=mqtt_config)
fast_mqtt.init_app(app)
# ------------------------------------------

@app.get("/")
async def root():
    return {"message": "FastAPI Turnstile Controller is running!"}

def command_topic(product_key: str, device_name: str):
    return f"/sys/{product_key}/{device_name}/thing/command/post"

@app.post("/open_turnstile/")
async def open_turnstile(product_key: str, device_name: str, door: int = 0):
    # Prepare MQTT message as per your protocol
    message = {
        "id": 2017,           # Example, you can generate a true random/incrementing one
        "taskNo": 10,
        "data": {
            "Door": door,
            "Open": 1
        },
        "version": "1.0",
        "method": "OpenDoor"
    }
    topic = command_topic(product_key, device_name)
    # Convert message to JSON string as required by MQTT
    await fast_mqtt.publish(topic, json.dumps(message))
    return {
        "result": "MQTT sent",
        "topic": topic,
        "payload": message
    }
