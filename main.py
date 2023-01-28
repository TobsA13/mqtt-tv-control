import argparse
import os
import subprocess
import sys
import time

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
mqttConfig = config["MQTT"]
tvConfig = config["TV"]

assert tvConfig.get("mqttPath", fallback="") != ""
assert tvConfig.get("method", fallback="").lower() in ["cec", "output"]

connected = False


def on_connect(client, data_object, flags, result):
    client.subscribe(f"{tvConfig.get('mqttPath')}/data")
    global connected
    connected = True


def on_message(mqtt_client, data_object, msg):
    """Default callback on MQTT message."""
    logger.error("Unknown MQTT topic: %s", msg.topic)


def on_message_command(mqtt_client, data_object, msg):
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
            subprocess.check_output('/bin/echo "on 0" | /usr/bin/sudo /usr/bin/cec-client -s -d 1', shell=True)
            logger.info("Turned on via CEC")
            time.sleep(5)
            subprocess.check_output('/bin/echo "as 0" | /usr/bin/sudo /usr/bin/cec-client -s -d 1', shell=True)
            logger.info("Switched input via output")
        else:
            subprocess.check_output('/bin/echo "standby 0" | /usr/bin/sudo /usr/bin/cec-client -s -d 1', shell=True)
            logger.info("Turned off via CEC")

    if tvConfig.get("method").lower() == "output":
        if on:
            subprocess.check_output('/usr/bin/sudo /usr/bin/vcgencmd display_power 1', shell=True)
            logger.info("Turned on via output")
        else:
            subprocess.check_output('/usr/bin/sudo /usr/bin/vcgencmd display_power 0', shell=True)
            logger.info("Turned off via output")


mqttc = mqtt.Client(
    client_id=mqttConfig.get("clientId", os.path.basename(sys.argv[0])),
)
mqttc.on_connect = on_connect
mqttc.message_callback_add(f"{tvConfig.get('mqttPath', fallback='')}/data", on_message_command)
mqttc.on_message = on_message

if mqttConfig.get("user", fallback="") != '':
    mqttc.username_pw_set(mqttConfig.get("user", fallback=""), mqttConfig.get("pass", fallback=""))

if mqttConfig.getboolean("tls", fallback=False):
    mqttc.tls_set()

mqttc.enable_logger(logger=logger)
mqttc.connect(mqttConfig.get("broker", fallback="localhost"), mqttConfig.getint("port", 1883))

logger.info("Starting mqtt client...")
if tvConfig.getboolean("enableHeartbeat", fallback=False):
    mqttc.loop_start()
    while not connected:
        logger.debug("Waiting for connect")
        time.sleep(1)
    while True:
        mqttc.publish(f"{tvConfig.get('mqttPath', fallback='')}/heartbeat", str(int(time.time())))
        time.sleep(10)
else:
    mqttc.loop_forever()
