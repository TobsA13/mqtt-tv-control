#!/usr/bin/env python3
import argparse
import os
import platform
import signal
import subprocess
import sys
import time
import threading
import queue

import paho.mqtt.client as mqtt
import configparser
import logging

LOG_FORMAT = "%(asctime)s %(levelname)s: %(message)s"
logging.basicConfig(format=LOG_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

parser = argparse.ArgumentParser(
    description='On/off a TV using MQTT',
    epilog='by Feuerwehr Wörnitz | TobsA')
parser.add_argument('configPath', help="Config file path")
parser.add_argument('-v', '--verbose', action='store_true')
args = parser.parse_args()

if args.verbose:
    logger.setLevel(logging.DEBUG)

config = configparser.ConfigParser()
logger.debug(f"Reading config file {args.configPath}")
config.read(args.configPath)
try:
    mqttConfig = config["MQTT"]
    tvConfig = config["TV"]
except KeyError:
    logger.critical("Failed to load config")
    exit(1)

assert tvConfig.get("mqttPath", fallback="") != ""
assert tvConfig.get("method", fallback="").lower() in ["cec", "output"]

connected = threading.Event()
stop = threading.Event()
cmd_queue = queue.Queue()


def signalhandler(signum):
    logger.info("Signal handler called with signal {}".format(signum))

    stop.set()
    mqttc.disconnect()
    logger.warning("exiting...")
    exit(0)


def on_connect(client, data_object, flags, result):
    client.subscribe(f"{tvConfig.get('mqttPath')}/cmd")
    data_object["connected"].set()


def on_message(mqtt_client, data_object, msg):
    """Default callback on MQTT message."""
    logger.error("Unknown MQTT topic: %s", msg.topic)


def on_message_command(mqtt_client, data_object, msg):
    logger = data_object["logger"]
    cmd_queue = data_object["cmd_queue"]
    logger.info(f"Received command: {msg.payload.decode('utf-8')}")
    if msg.payload.decode("utf-8").lower() == "on":
        on = True
    elif msg.payload.decode("utf-8").lower() == "off":
        on = False
    else:
        logger.error("Unknown command!")
        return

    if tvConfig.get("method").lower() == "cec":
        if on:
            cmd_queue.put(("cec_on", 5))
            cmd_queue.put(("cec_as", 5))
        else:
            cmd_queue.put(("cec_off", 5))

    if tvConfig.get("method").lower() == "output":
        if on:
            cmd_queue.put(("output_on", 1))
        else:
            cmd_queue.put(("output_on", 1))


def command_worker(mqtt_client, cmd_queue, stop, tvConfig, logger):
    old_status = None
    while not stop.is_set():
        try:
            data = cmd_queue.get_nowait()
            cmd = data[0]
            logger.info(f"Running command: {cmd}")

            if cmd == "cec_on":
                subprocess.check_output('/bin/echo "on 0" | /usr/bin/sudo /usr/bin/cec-client -s -d 1', shell=True)
                logger.info("Turned on via CEC")
            elif cmd == "cec_as":
                subprocess.check_output('/bin/echo "as 0" | /usr/bin/sudo /usr/bin/cec-client -s -d 1', shell=True)
                logger.info("Switched input via CEC")
            elif cmd == "cec_off":
                subprocess.check_output('/bin/echo "standby 0" | /usr/bin/sudo /usr/bin/cec-client -s -d 1', shell=True)
                logger.info("Turned off via CEC")

            elif cmd == "output_on":
                subprocess.check_output('/usr/bin/sudo /usr/bin/vcgencmd display_power 1', shell=True)
                logger.info("Turned on via output")
            elif cmd == "output_off":
                subprocess.check_output('/usr/bin/sudo /usr/bin/vcgencmd display_power 0', shell=True)
                logger.info("Turned off via output")

            if cmd in ["cec_status", "output_status"]:
                status = None
                if cmd == "cec_status":
                    status = subprocess.check_output('/bin/echo "pow 0" | /usr/bin/sudo /usr/bin/cec-client -s -d 1 | grep "power" | cut -d" " -f3', shell=True)
                    status = status.decode("UTF-8").strip()
                    status = status == "on"
                elif cmd == "output_status":
                    status = subprocess.check_output('/usr/bin/sudo /usr/bin/vcgencmd display_power | cut -d "=" -f 2', shell=True)
                    status = status.decode("UTF-8").strip()
                    status = status == "1"

                if old_status != status:
                    old_status = status
                    mqtt_client.publish(f"{tvConfig.get('mqttPath', fallback='')}/status", "on" if status else "off")

            time.sleep(data[1])
        except queue.Empty:
            time.sleep(1)
        except subprocess.CalledProcessError:
            logger.error("Error running the command")
            time.sleep(1)


mqttc = mqtt.Client(
    client_id=mqttConfig.get("clientId", os.path.basename(sys.argv[0])),
    userdata={
        "logger": logger,
        "cmd_queue": cmd_queue,
        "connected": connected
    }
)
mqttc.on_connect = on_connect
mqttc.message_callback_add(f"{tvConfig.get('mqttPath', fallback='')}/cmd", on_message_command)
mqttc.on_message = on_message

if mqttConfig.get("user", fallback="") != '':
    mqttc.username_pw_set(mqttConfig.get("user", fallback=""), mqttConfig.get("pass", fallback=""))

if mqttConfig.getboolean("tls", fallback=False):
    mqttc.tls_set()

mqttc.enable_logger(logger=logger)
mqttc.connect(mqttConfig.get("broker", fallback="localhost"), mqttConfig.getint("port", 1883))

threading.Thread(target=command_worker, args=[mqttc, cmd_queue, stop, tvConfig, logger]).start()

signal.signal(signal.SIGTERM, signalhandler)
if platform.system() == 'Linux':
    signal.signal(signal.SIGHUP, signalhandler)

logger.info("Starting mqtt client...")
mqttc.loop_start()
while not connected.is_set():
    logger.info("Waiting for connect")
    time.sleep(1)

try:
    while not stop.is_set():
        logger.debug("Adding status request to queue")
        if tvConfig.get("method").lower() == "cec":
            cmd_queue.put(("cec_status", 1))
        if tvConfig.get("method").lower() == "output":
            cmd_queue.put(("output_status", 1))

        if tvConfig.getboolean("enableHeartbeat", fallback=False):
            mqttc.publish(f"{tvConfig.get('mqttPath', fallback='')}/heartbeat", str(int(time.time())))

        time.sleep(30)
except KeyboardInterrupt:
    signalhandler("KeyboardInterrupt")
