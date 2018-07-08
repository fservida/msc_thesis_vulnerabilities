import json
import socket

import requests
import argparse
import sys


class QBee:
    # SETTINGS
    __DST_PORT = "4848"
    __SERVICE = "WEBDIS"
    __USER_AGENT = "okhttp/3.3.0"
    __CONTENT_TYPE = "application/json;charset=UTF-8"
    __ACCEPT_ENCODING = "gzip"

    __PROTOCOL = "http"
    __PORT = "15700"

    __cookies_basic_template = dict(
        DST_PORT=__DST_PORT,
        JSESSIONID=None,
        GC_ID=None,
    )

    __cookies_extended_template = dict(
        JSESSIONID=None,
        GC_ID=None,
        LD_ID=None,
        SERVICE=__SERVICE,
    )

    __headers = {
        'User-agent': __USER_AGENT,
        'Content-type': __CONTENT_TYPE,
        'Accept-encoding': __ACCEPT_ENCODING,
    }

    def __init__(self, ip, session_id, gc_id, ld_id):
        self.__ip = None
        self.ip = ip
        self.__gc_id = str(gc_id)
        self.__ld_id = str(ld_id)
        self.__jsessionid = None
        self.jsessionid = session_id
        if self.__verify_camera():
            print("JSESSIONID and GC_ID valid")
        else:
            print("JSESSIONID or GC_ID are invalid or expired")
        self.__get_camera_local_config()

    @property
    def jsessionid(self):
        return self.__jsessionid

    @jsessionid.setter
    def jsessionid(self, session_id):
        self.__jsessionid = str(session_id)

    @property
    def ip(self):
        return self.__ip

    @ip.setter
    def ip(self, ip):
        # Check if valid ip address
        ip = str(ip)
        try:
            socket.inet_pton(socket.AF_INET, ip)
        except socket.error:
            raise ValueError("Invalid IP Address entered")

        self.__ip = ip

    @property
    def __cookies_extended(self):
        # Joins the template extended cookie with the valid session id
        return dict(QBee.__cookies_extended_template, JSESSIONID=self.jsessionid, GC_ID=self.__gc_id,
                    LD_ID=self.__ld_id)

    @property
    def __cookies_basic(self):
        # Joins the template extended cookie with the valid session id
        return dict(QBee.__cookies_basic_template, JSESSIONID=self.jsessionid, GC_ID=self.__gc_id)

    @property
    def __host(self):
        return "{}://{}:{}/".format(QBee.__PROTOCOL, self.ip, QBee.__PORT)

    def __url(self, path):
        return self.__host + path

    @staticmethod
    def __check_status(response: requests.Response):
        if response.status_code == 200:
            return True
        elif response.status_code == 403:
            raise ConnectionRefusedError(
                "Connection refused: the cookies provided are likely invalid or expired, check the LD_ID")
        else:
            raise ConnectionError("The connection to the camera failed: ", getattr(response, 'text', ""))

    def __get_camera_local_config(self):
        url = self.__url("config/get?service=webdis")
        response = requests.get(url, cookies=self.__cookies_extended, headers=QBee.__headers)

        self.__check_status(response)
        self.__settings = json.loads(response.text)

    @property
    def settings(self):
        # Create a copy of the settings and return it
        return dict(self.__settings)

    def __verify_camera(self):
        url = self.__url("verify")
        response = requests.get(url, cookies=self.__cookies_basic, headers=QBee.__headers)

        return self.__check_status(response)

    def get_camera_local_event(self):
        url = self.__url("event?service=webdis&transport=stream")
        response = requests.get(url, cookies=self.__cookies_extended, headers=QBee.__headers)

        self.__check_status(response)
        return json.loads(response.text)

    def get_camera_technical_details(self):
        url = self.__url("technical?service=webdis")
        response = requests.get(url, cookies=self.__cookies_extended, headers=QBee.__headers)

        self.__check_status(response)
        self.__technical_details = json.loads(response.text)

    def __update_camera_local_config(self, data):
        url = self.__url("config/set?service=webdis")
        response = requests.post(url, json=data, cookies=self.__cookies_extended, headers=QBee.__headers)

        return self.__check_status(response)

    def __change_setting(self, setting, new_value):
        if setting not in self.__settings:
            raise ValueError("Invalid setting name")

        data = {
            setting: new_value
        }

        self.__update_camera_local_config(data)
        self.__get_camera_local_config()

    def __toggle_status(self, setting, status):
        if status and not getattr(self, setting):
            self.__change_setting(setting, 'on')
        elif not status and getattr(self, setting):
            self.__change_setting(setting, 'off')
        else:
            # No change needed
            pass

    @property
    def privacy_button(self):
        return self.__settings.get('privacy_button') == 'on'

    @privacy_button.setter
    def privacy_button(self, status):
        self.__toggle_status('privacy_button', status)

    @property
    def privacy(self):
        return self.__settings.get('privacy') == 'on'

    @privacy.setter
    def privacy(self, status):
        self.__toggle_status('privacy', status)

    @property
    def status_led(self):
        return self.__settings.get('status_led') == 'on'

    @status_led.setter
    def status_led(self, status):
        self.__toggle_status('status_led', status)

    @property
    def motion_detection(self):
        return self.__settings.get('motion_detection') == 'on'

    @motion_detection.setter
    def motion_detection(self, status):
        self.__toggle_status('motion_detection', status)

    # Siren setting status not available
    # @property
    # def siren(self):
    #     return self.__settings.get('siren') == 'on'
    #
    # @siren.setter
    # def siren(self, status):
    #     self.__toggle_status('siren', status)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Python Interface to interact with QBee camera")
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('-v', '--verbose', help="Enable debugging output", action='store_true')
    parser.add_argument('input', help='File input (default: std in)', nargs='?',
                        type=argparse.FileType('r'), default=sys.stdin)

    args = parser.parse_args()

    cookies = json.load(args.input)

    # qbee = QBee("10.20.30.15", session_id="07e82b16-cb7d-407b-99d2-a1aba854639a", gc_id=14602, ld_id=14887)

    qbee = QBee(cookies['IP'], session_id=cookies['JSESSIONID'], gc_id=cookies['GC_ID'], ld_id=cookies['LD_ID'])

    # print(qbee.settings)
    print("Status Led: ", qbee.status_led)
    print("Motion Detection: ", qbee.motion_detection)
    print("Privacy: ", qbee.privacy)
    print("Privacy Button Enabled: ", qbee.privacy_button)

    qbee.motion_detection = False
    qbee.status_led = False
    qbee.privacy_button = True
    qbee.privacy = False

    # print(qbee.settings)
    print("Status Led: ", qbee.status_led)
    print("Motion Detection: ", qbee.motion_detection)
    print("Privacy: ", qbee.privacy)
    print("Privacy Button Enabled: ", qbee.privacy_button)

    # print(qbee.get_camera_technical_details())
