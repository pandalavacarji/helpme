import socket
import struct
import threading
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any
import os

from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ControllerInfo:
    ip_address: str
    serial_number: str
    model_type: int
    model_description: str
    version: str
    mac_address: str
    port: int
    socket_obj: Any = field(default=None)
    last_heartbeat: float = field(default_factory=time.time)

class AccessControllerServer:
    def __init__(self):
        self.controllers: Dict[str, ControllerInfo] = {}
        self.udp_socket = None
        self.running = False
        self.tcp_thread = None
        self.udp_thread = None
        self.heartbeat_thread = None
        self.model_mapping = {
            1: "TCP Single door",
            2: "TCP Dual door",
            3: "TCP four door",
            6: "TCP elevator controller",
            11: "TCP gate controller",
            13: "Cloud+B version controller",
            14: "Cloud+C version controller",
            0x71: "Practical TCP Single door",
            0x9E: "TCP network all-in-one machine -3rd generation",
            0x90: "TCP gate controller -3rd generation",
            0x91: "TCP Single Gate-3rd Generation",
            0x72: "Practical TCP Dual door",
            0x92: "TCP Dual door Generation 3",
            0x94: "TCP Four door - Generation 3",
            0x9C: "Cloud Gate Machine Generation 3",
            0xB4: "Cloud+B controller 4th generation",
            0xC4: "Cloud+C controller 4th generation",
            0xCB: "Cloud+2 door controller 4th generation",
            0xCD: "Cloud+4 door controller 4th generation",
            0xE3: "Cloud Elevator Controller 3rd Generation"
        }

    def start_server(self):
        self.running = True
        port = 9000
        self.udp_thread = threading.Thread(target=self._udp_discovery_listener, args=(port,))
        self.udp_thread.daemon = True
        self.udp_thread.start()
        self.tcp_thread = threading.Thread(target=self._tcp_connection_manager)
        self.tcp_thread.daemon = True
        self.tcp_thread.start()
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_monitor)
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()
        logger.info(f"Access Controller Server started on port {port}")

    def stop_server(self):
        self.running = False
        for controller in self.controllers.values():
            if controller.socket_obj:
                controller.socket_obj.close()
        if self.udp_socket:
            self.udp_socket.close()
        logger.info("Access Controller Server stopped")

    def _udp_discovery_listener(self, port: int):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_socket.settimeout(1.0)
        try:
            self.udp_socket.bind(('0.0.0.0', port))
            logger.info(f"Listening for controller discovery responses on UDP port {port}")
        except Exception as e:
            logger.error(f"Failed to bind UDP socket: {e}")
            return
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(1024)
                self._parse_discovery_response(data, addr[0])
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving UDP data: {e}")

    def send_discovery_broadcast(self):
        if not self.udp_socket:
            return
        discovery_packet = bytes.fromhex('02A099000000003B03')
        broadcast_addr = ('255.255.255.255', 9000)
        try:
            self.udp_socket.sendto(discovery_packet, broadcast_addr)
            logger.info("Sent controller discovery broadcast")
        except Exception as e:
            logger.error(f"Failed to send discovery broadcast: {e}")

    def send_discovery_direct(self, turnstile_ip: str):
        if not self.udp_socket:
            return
        discovery_packet = bytes.fromhex('02A099000000003B03')
        try:
            self.udp_socket.sendto(discovery_packet, (turnstile_ip, 9000))
            logger.info(f"Sent discovery to {turnstile_ip}")
        except Exception as e:
            logger.error(f"Failed to send discovery to {turnstile_ip}: {e}")

    def _parse_discovery_response(self, data: bytes, ip_address: str):
        try:
            if len(data) < 30 or data[0] != 0x02 or data[-1] != 0x03:
                return
            calculated_cs = 0
            for byte in data[1:-2]:
                calculated_cs ^= byte
            if calculated_cs != data[-2]:
                logger.warning(f"Invalid checksum from {ip_address}")
                return
            serial_bytes = data[7:13]
            serial_number = ''.join(f'{b:02X}' for b in serial_bytes)
            if serial_number in self.controllers:
                self.controllers[serial_number].ip_address = ip_address
                self.controllers[serial_number].last_heartbeat = time.time()
                logger.info(f"Rediscovered controller {serial_number} at {ip_address}")
                return
            model_type = data[13]
            model_description = self.model_mapping.get(model_type, "Unknown model")
            version = f"{data[14]}.{data[15]}"
            mac_address = f"{data[28]:02X}"
            port = struct.unpack('<H', data[22:24])[0]
            controller = ControllerInfo(
                ip_address=ip_address,
                serial_number=serial_number,
                model_type=model_type,
                model_description=model_description,
                version=version,
                mac_address=mac_address,
                port=port
            )
            self.controllers[serial_number] = controller
            logger.info(f"Discovered controller {serial_number} at {ip_address}:{port} - {model_description}")
        except Exception as e:
            logger.error(f"Error parsing discovery response from {ip_address}: {e}")

    def _tcp_connection_manager(self):
        while self.running:
            for serial, controller in list(self.controllers.items()):
                try:
                    if controller.socket_obj is None:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5.0)
                        sock.connect((controller.ip_address, controller.port))
                        controller.socket_obj = sock
                        controller.last_heartbeat = time.time()
                        logger.info(f"Connected to controller {serial} at {controller.ip_address}:{controller.port}")
                        thread = threading.Thread(target=self._handle_controller_messages, args=(controller,))
                        thread.daemon = True
                        thread.start()
                except Exception as e:
                    logger.warning(f"Failed to connect to controller {serial}: {e}")
                    time.sleep(5)
            time.sleep(1)

    def _handle_controller_messages(self, controller: ControllerInfo):
        sock = controller.socket_obj
        buffer = b''
        while self.running and sock:
            try:
                data = sock.recv(1024)
                if not data:
                    logger.warning(f"Connection closed by controller {controller.serial_number}")
                    sock.close()
                    controller.socket_obj = None
                    break
                buffer += data
                while len(buffer) >= 5:
                    start_idx = buffer.find(b'\x02')
                    if start_idx == -1:
                        buffer = b''
                        break
                    buffer = buffer[start_idx:]
                    if len(buffer) < 7:
                        break
                    length_l = buffer[5]
                    length_h = buffer[6]
                    data_length = length_l + (length_h << 8)
                    total_length = 7 + data_length + 2
                    if len(buffer) < total_length:
                        break
                    message = buffer[:total_length]
                    buffer = buffer[total_length:]
                    calculated_cs = 0
                    for byte in message[1:-2]:
                        calculated_cs ^= byte
                    if calculated_cs != message[-2]:
                        logger.warning(f"Invalid checksum from controller {controller.serial_number}")
                        continue
                    if message[-1] != 0x03:
                        logger.warning(f"Invalid ETX from controller {controller.serial_number}")
                        continue
                    self._process_controller_message(controller, message)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error handling messages from controller {controller.serial_number}: {e}")
                if sock:
                    sock.close()
                controller.socket_obj = None
                break

    def _process_controller_message(self, controller: ControllerInfo, message: bytes):
        command = message[2]
        if command == 0x56:
            controller.last_heartbeat = time.time()
            self._handle_heartbeat(controller, message)
        elif command == 0x53:
            self._handle_card_swipe(controller, message)
        elif command == 0x54:
            self._handle_alarm_record(controller, message)
        elif command == 0x52:
            self._handle_card_state(controller, message)
        else:
            logger.info(f"Received unknown command 0x{command:02X} from controller {controller.serial_number}")

    def _handle_heartbeat(self, controller: ControllerInfo, message: bytes):
        response = self._build_response_frame(0x56, bytes([0x00, 0x00]))
        self._send_to_controller(controller, response)
        logger.debug(f"Received heartbeat from controller {controller.serial_number}")

    def _handle_card_swipe(self, controller: ControllerInfo, message: bytes):
        record_serial = message[-4] if len(message) > 4 else 0
        response = self._build_response_frame(0x53, bytes([record_serial]))
        self._send_to_controller(controller, response)
        logger.info(f"Received card swipe from controller {controller.serial_number}")

    def _handle_alarm_record(self, controller: ControllerInfo, message: bytes):
        record_serial = message[-3] if len(message) > 3 else 0
        response = self._build_response_frame(0x54, bytes([record_serial]))
        self._send_to_controller(controller, response)
        logger.info(f"Received alarm record from controller {controller.serial_number}")

    def _handle_card_state(self, controller: ControllerInfo, message: bytes):
        record_serial = message[-3] if len(message) > 3 else 0
        response = self._build_response_frame(0x52, bytes([record_serial]))
        self._send_to_controller(controller, response)
        logger.info(f"Received card state record from controller {controller.serial_number}")

    def _build_response_frame(self, command: int, data: bytes = b'') -> bytes:
        frame = bytearray()
        frame.append(0x02)
        frame.append(0xA0)
        frame.append(command)
        frame.append(0xFF)
        frame.append(0x00)
        data_length = len(data)
        frame.append(data_length & 0xFF)
        frame.append((data_length >> 8) & 0xFF)
        frame.extend(data)
        checksum = 0
        for byte in frame[1:]:
            checksum ^= byte
        frame.append(checksum)
        frame.append(0x03)
        return bytes(frame)

    def _send_to_controller(self, controller: ControllerInfo, data: bytes):
        if controller.socket_obj:
            try:
                controller.socket_obj.sendall(data)
            except Exception as e:
                logger.error(f"Failed to send data to controller {controller.serial_number}: {e}")
                controller.socket_obj.close()
                controller.socket_obj = None

    def _heartbeat_monitor(self):
        while self.running:
            for serial, controller in list(self.controllers.items()):
                if controller.socket_obj and time.time() - controller.last_heartbeat > 15:
                    logger.warning(f"Controller {serial} heartbeat timeout, reconnecting")
                    controller.socket_obj.close()
                    controller.socket_obj = None
            time.sleep(5)

    def open_door(self, controller_serial: str, door_number: int = 1) -> bool:
        if controller_serial not in self.controllers:
            logger.error(f"Controller {controller_serial} not found")
            return False
        controller = self.controllers[controller_serial]
        data = bytes([door_number])
        command = self._build_response_frame(0x2C, data)
        self._send_to_controller(controller, command)
        logger.info(f"Sent open door command to controller {controller_serial}, door {door_number}")
        return True

    def set_time(self, controller_serial: str) -> bool:
        if controller_serial not in self.controllers:
            logger.error(f"Controller {controller_serial} not found")
            return False
        controller = self.controllers[controller_serial]
        now = time.localtime()
        time_data = bytes([
            now.tm_sec,
            now.tm_min,
            now.tm_hour,
            now.tm_wday + 1,
            now.tm_mday,
            now.tm_mon,
            now.tm_year - 2000
        ])
        command = self._build_response_frame(0x07, time_data)
        self._send_to_controller(controller, command)
        logger.info(f"Sent time synchronization to controller {controller_serial}")
        return True

    def list_controllers(self) -> List[Dict]:
        return [
            {
                'serial_number': c.serial_number,
                'ip_address': c.ip_address,
                'model': c.model_description,
                'version': c.version,
                'connected': c.socket_obj is not None
            }
            for c in self.controllers.values()
        ]

    def get_server_info(self) -> Dict:
        return {
            'port': 9000,
            'running': self.running,
            'controllers_count': len(self.controllers)
        }

app = Flask(__name__)
server = AccessControllerServer()
threads_started = False

@app.before_request
def ensure_threads_started():
    global threads_started
    if not threads_started:
        server.start_server()
        threading.Timer(2.0, server.send_discovery_broadcast).start()
        threads_started = True

@app.route('/')
def index():
    return jsonify({'status': 'Access Controller Server Running', 'server_info': server.get_server_info()})

@app.route('/controllers')
def list_controllers():
    return jsonify(server.list_controllers())

@app.route('/discover')
def discover_controllers():
    server.send_discovery_broadcast()
    return jsonify({'status': 'Discovery broadcast sent'})

@app.route('/discover/<ip>')
def discover_specific(ip):
    server.send_discovery_direct(ip)
    return jsonify({'status': f'Discovery sent to {ip}'})

@app.route('/open-door/<serial>')
def open_door(serial):
    door = request.args.get('door', 1, type=int)
    success = server.open_door(serial, door)
    return jsonify({'success': success, 'serial': serial, 'door': door})

@app.route('/set-time/<serial>')
def set_time(serial):
    success = server.set_time(serial)
    return jsonify({'success': success, 'serial': serial})

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'controllers': len(server.controllers)})

@app.route('/api/AcsEvent', methods=['POST'])
def handle_gate_event():
    data = request.get_json()
    controller_serial = data.get('serial_number') or data.get('SerialNo') or None
    ip_address = request.remote_addr
    if controller_serial:
        if controller_serial not in server.controllers:
            controller = ControllerInfo(
                ip_address=ip_address,
                serial_number=controller_serial,
                model_type=0,
                model_description="Unknown (via HTTP POST)",
                version="N/A",
                mac_address="N/A",
                port=9000
            )
            server.controllers[controller_serial] = controller
            logger.info(f"Added controller {controller_serial} from HTTP POST event")
        else:
            server.controllers[controller_serial].last_heartbeat = time.time()
    logger.info(f"Received gate event: {data}")
    return jsonify({'status': 'event received'}), 200

@app.route('/api/AcsStatus', methods=['POST'])
def handle_gate_status():
    data = request.get_json()
    controller_serial = data.get('serial_number') or data.get('SerialNo') or None
    ip_address = request.remote_addr
    if controller_serial:
        if controller_serial in server.controllers:
            server.controllers[controller_serial].last_heartbeat = time.time()
        else:
            controller = ControllerInfo(
                ip_address=ip_address,
                serial_number=controller_serial,
                model_type=0,
                model_description="Unknown (via HTTP POST)",
                version="N/A",
                mac_address="N/A",
                port=9000
            )
            server.controllers[controller_serial] = controller
            logger.info(f"Added controller {controller_serial} from HTTP POST status")
    logger.info(f"Received heartbeat: {data}")
    return jsonify({'status': 'status received'}), 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=9000, debug=False)
