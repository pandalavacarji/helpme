from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "FastAPI Turnstile Controller is running!"}

@app.post("/open_turnstile/")
async def open_turnstile(product_key: str, device_name: str, door: int = 0):
    return {
        "result": "received",
        "product_key": product_key,
        "device_name": device_name,
        "door": door
    }
