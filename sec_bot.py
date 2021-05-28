#!/bin/env python3.6
# -*- coding: utf-8 -*-

__author__ = "Oleg Evdokimov"
__disclaimer__ = """

Зависимости:
 clickhouse-driver==0.1.5
 jira==2.0.0
 loguru==0.5.3
 mailru-im-bot==0.0.14
 PyYAML==5.3.1
 schedule==0.6.0

Manuals: 
 https://myteam.mail.ru/botapi/
"""

import os
import sys
from typing import Dict
from functools import wraps

import schedule
import re
import yaml
import hashlib
import socket
import sqlite3
import requests
import json

from loguru import logger
from time import sleep
from datetime import datetime, timedelta
from bot.bot import Bot
from bot.event import Event, EventType
from bot.handler import MessageHandler, CommandHandler, BotButtonCommandHandler, UnknownCommandHandler
from requests.exceptions import ReadTimeout, ConnectTimeout, ConnectionError
from clickhouse_driver import Client
from collections import deque
from jira import JIRA
from collections import namedtuple
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, AddressValueError

CONFIG_FILE = '/configs/secure_bot.yaml'


# очередь для отпарсенных логов secure и tacacs (очередь событий)
LogEventsQueue = deque()
# очередь для аггрегированных логов tacacs (очередь событий)
TacEventsQueue = deque()
# очередь для аггрегированных логов secure (очередь событий)
SecureEventsQueue = deque()
# очередь для проверки source ip (очередь событий)
SourceEventsQueue = deque()
# очередь для событий, по которым юзеру отправлен запрос и ожидается ответ
RequestEventsQueue = deque()
# очередь для событий, по которым требуется создать jira-инц
AlarmEventsQueue = deque()


@dataclass
class DBQuery:
    table: str
    keys: list
    sql_query: str


class User:
    def __init__(self, usertype, login, chat_id):
        self._usertype = usertype
        self._login = login
        self._chat_id = chat_id

    @property
    def usertype(self):
        return self._usertype

    @property
    def login(self):
        return self._login

    @property
    def chat_id(self):
        return self._chat_id

    def __repr__(self):
        return f'{self._usertype} : {self._login} : {self._chat_id}'


class UserList:
    def __init__(self, usertype=None, user_dict=None):
        self.usertype_flag = None
        self.users = []
        if isinstance(user_dict, dict) and usertype:
            for uname, chat_id in user_dict.items():
                user = User(usertype, uname, chat_id)
                self.users.append(user)

    def __add__(self, new_user):
        if isinstance(new_user, User):
            self.users.append(new_user)
        return self

    def __setitem__(self, old_user: User, new_login: str):
        self.users.remove(old_user)
        old_user._login = new_login
        self.users.append(old_user)

    def __iter__(self):
        for u in self.users:
            yield u

    def __len__(self):
        return len(self.users)

    def __repr__(self):
        res = ''
        for u in self.users:
            res += '{}\n'.format(''.join(u.__repr__()))
        return res

    def __format__(self, usertype):
        res = ''
        for u in self.users:
            if u.usertype == usertype:
                res += '{}\n'.format(''.join(u.__repr__()))
        return res

    def __getattribute__(self, item):
        if item in (NETWORK, SERVER):
            self.usertype_flag = item
            return self
        elif item in ('logins',):
            res = []
            for u in self.users:
                if u.usertype == self.usertype_flag:
                    res.append(u.login)
            return res
        return super().__getattribute__(item)

    def get_users(self, usertype=None, login=None, chat_id=None):
        user_list = []
        for u in self.users:
            if u.usertype == usertype or u.login == login or u.chat_id == chat_id:
                user_list.append(u)
        return user_list

    def get_user(self, usertype, login=None, chat_id=None):
        for u in self.users:
            if u.usertype == usertype and (u.login == login or u.chat_id == chat_id):
                return u
        # if user not found
        return User(usertype, UNKNOWN_USER, USER_ADMIN_CHAT_ID)

    def update_db(self, usertype=None, user_dict=None):
        if isinstance(user_dict, dict) and usertype:
            for uname, chat_id in user_dict.items():
                user = User(usertype, uname, chat_id)
                self.users.append(user)


# класс для описания События (событие - запись из лог файла подпадающая под условие)
class EventLogClass:
    def __init__(self, log_date, alarm_type, username, login, host, src_ip, text, descr=''):
        self.date = log_date
        self.alarm_type = alarm_type
        self.username = username
        self.login = login
        self.host = host
        self.src_ip = src_ip
        self.text = text
        self.descr = descr
        self.request = False
        self.request_time = None
        self.second_request = False
        self.reply = False
        self.alarm = False
        self.hash = None

    def set_request(self, request_time):
        self.request = True
        self.request_time = request_time

    def set_reply(self):
        self.reply = True

    def set_alarm(self, flag):
        self.alarm = flag

    def set_hash(self, msg_text):
        self.hash = self.get_hash(msg_text)


    @staticmethod
    def get_hash(text):
        digest = hashlib.new('md5')
        digest.update(text.encode())
        return digest.hexdigest()

    def show(self):
        return ('hash_id: {} \n date: {} - type: {} - user: {} - login: {} - host: {} - src: {} - text: {}'.
                format(self.hash,
                       self.date,
                       self.alarm_type,
                       self.username,
                       self.login,
                       self.host,
                       self.src_ip,
                       self.text))



try:
    secure_bot = Bot(token=TOKEN, api_url_base=MYTEAM_URL)
except Exception as error:
    logger.error(f'\nCannot connect to the Bot API: {error.with_traceback(sys.exc_info()[2])}')
    os._exit(-1)



def buttons_answer_cb(bot, event):
    if event.data['callbackData'] == "call_back_yes":
        data = {
            'from': {'firstName': event.data['from']['firstName'],
                     'lastName': event.data['from']['lastName'],
                     'userId': event.data['from']['userId']},
            'chat': {'chatId': event.data['message']['chat']['chatId'],
                     'type': event.data['message']['chat']['type']},
            'msgId': event.data['message']['msgId'],
            'text': 'Yes',
            'timestamp': event.data['message']['timestamp']
        }
        yes_msg = Event(EventType.NEW_MESSAGE, data)
        msg_text = event.data['message']['text']
        hash_log = EventLogClass.get_hash(msg_text)
        reply_bot(bot, yes_msg, hash_log)

    elif event.data['callbackData'] == "call_back_no":
        data = {
            'from': {'firstName': event.data['from']['firstName'],
                     'lastName': event.data['from']['lastName'],
                     'userId': event.data['from']['userId']},
            'chat': {'chatId': event.data['message']['chat']['chatId'],
                     'type': event.data['message']['chat']['type']},
            'msgId': event.data['message']['msgId'],
            'text': 'No',
            'timestamp': event.data['message']['timestamp']
        }
        no_msg = Event(EventType.NEW_MESSAGE, data)
        msg_text = event.data['message']['text']
        hash_log = EventLogClass.get_hash(msg_text)
        reply_bot(bot, no_msg, hash_log)


def send_msg(chat_id, message, with_buttons=False):
    try:
        if not with_buttons:
            mt_response = secure_bot.send_text(chat_id=chat_id, text=message)
            logger.info(f'Myteam answer: {mt_response}')
        else:
            mt_response = secure_bot.send_text(
                chat_id=chat_id,
                text=message,
                inline_keyboard_markup="{}".format(json.dumps([[
                    {"text": "ДА", "callbackData": "call_back_yes", "style": "primary"},
                    {"text": "НЕТ", "callbackData": "call_back_no", "style": "attention"}]])))
        if not mt_response.json()['ok']:
            text_to_chat = 'ERROR: check_alarm_queue(). Myteam message delivery error \n ' \
                           'response: {} \n ' \
                           'message: {} \n ' \
                           'user: {}'.format(mt_response.json(), message, chat_id)
            # myteam delivery
            secure_bot.send_text(chat_id=USER_ADMIN_CHAT_ID, text=text_to_chat)
            # telegram delivery
            data = {'chat_id': TG_MAJOR, 'text': text_to_chat}
            tg_response = requests.post(TG_URL + TG_TOKEN + '/sendMessage', data=data, proxies=TG_PROXIES)
            logger.info(f'Send_alarm_message: {tg_response.json()}, chat_id: {chat_id}')
        logger.info(f'Send_message: {message}, user: {chat_id}')
    except Exception as e:
        text_debug = f'{send_msg.__name__}\nMessage: {message}\nError: {e}'
        logger.error(text_debug)


# get DATA from DB
def get_cmdb():
    request = CMDB_API_URL + 'NetworkHostListWithIP'
    try:
        json_response = requests.get(request, auth=(CMDB_API_USER, CMDB_API_PASS), timeout=(3, 5)).text
        cmdb_dict = json.loads(json_response)
    except (ReadTimeout, ConnectTimeout, ConnectionError, json.decoder.JSONDecodeError) as e:
        text = f'{get_cmdb.__name__}. CMDB connection error. {e}'
        logger.error(text)
        send_msg(USER_ADMIN_CHAT_ID, text)
        return False
    if cmdb_dict:
        return cmdb_dict
    else:
        text = f'{get_cmdb.__name__}. Cannot fetch data from CMDB.'
        logger.error(text)
        send_msg(USER_ADMIN_CHAT_ID, text)
        return False


def clear_cmdb_table():
    db_table = 'NetworkHostListWithIP'
    query_drop = 'DROP TABLE IF EXISTS {}'.format(db_table)
    query_vacuum = 'VACUUM'
    query_create = """
       CREATE TABLE IF NOT EXISTS {} (
       HostName text NOT NULL,
       HostState text NOT NULL,
       IP text,
       HardwareModel_Name text,
       NetworkRoles text,
       OrgUnitName text);
   """.format(db_table)
    try:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        cursor.execute(query_drop)
        cursor.execute(query_create)
        cursor.execute(query_vacuum)
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        text = f'ERROR: {clear_cmdb_table.__name__}. {e}'
        send_msg(USER_ADMIN_CHAT_ID, text)
        logger.error(e)
        return False


def clone_cmdb_to_local():
    logger.info(f'{clone_cmdb_to_local.__name__}')
    db_table = 'NetworkHostListWithIP'
    cmdb_dict = get_cmdb()
    if cmdb_dict is False:
        return False
    cmdb_list = list()
    for cd in cmdb_dict:
        cmdb_tuple = (
        cd['HostName'], cd['HostState'], cd['IP'], cd['HardwareModel_Name'], cd['NetworkRoles'], cd['OrgUnitName'])
        cmdb_list.append(cmdb_tuple)
    clear_cmdb_table()
    try:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        query = 'INSERT INTO {} ({}, {}, {}, {}, {}, {}) VALUES (?, ?, ?, ?, ?, ?)' \
            .format(db_table, 'HostName', 'HostState', 'IP', 'HardwareModel_Name', 'NetworkRoles', 'OrgUnitName')
        cursor.executemany(query, cmdb_list)
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except sqlite3.Error as e:
        text = f'SQLite error in clone_cmdb_to_local(): {e}'
        send_msg(USER_ADMIN_CHAT_ID, text)
        logger.error(text)
        return False


def read_db(query):
    global NetworkHostListDB
    query_request = f'{query.sql_query} {query.table}'
    keys = query.keys
    fetch_db_list = []
    try:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        cursor.execute(query_request)
        for row in cursor:
            i = 0
            item_db_dict = {}
            for key in keys:
                item_db_dict[key] = row[i]
                i += 1
            fetch_db_list.append(item_db_dict)
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error(f'{e.with_traceback(sys.exc_info()[2])}')
        return False
    NetworkHostListDB = fetch_db_list
    return True


def get_host_db(key, value, outbound_key):
    for item in NetworkHostListDB:
        if item.get(key) == value:
            return item[outbound_key]
    return value


def is_valid_src_ip(src, valid_sources):
    for valid_src in valid_sources:
        try:
            if src == valid_src or IPv4Address(src) in IPv4Network(valid_src):
                return True
        except AddressValueError:
            logger.error(f'AddressValueError in {is_valid_src_ip.__name__}')
    return False


def parse_username(usertype, user_login):
    logins: list = []
    if usertype == SERVER:
        logins = USERS.server.logins
    elif usertype == NETWORK:
        logins = USERS.network.logins
    pattern = re.compile('|'.join(logins))
    suspicious_user = pattern.search(user_login)
    if not suspicious_user:
        return str('')
    return suspicious_user.group()


# парсим логи из базы за время PARSE_TIME с задержкой DELAY_TIME от текущего времени
def parse_log(db_client, log_template_alarm_list, log_template_info_list, alarm_types):
    global DATE_PARSE_BEGIN, BOT_ALIVE
    current_date = datetime.now()
    date2 = current_date - timedelta(seconds=DELAY_TIME)
    date1 = DATE_PARSE_BEGIN + timedelta(seconds=1)
    DATE_PARSE_BEGIN = date2
    date1_sql = date1.strftime("%Y-%m-%d %H:%M:%S")
    date2_sql = date2.strftime("%Y-%m-%d %H:%M:%S")
    query = """
    WITH
    toDateTime('{}') as date_1,
    toDateTime('{}') as date_2    
    SELECT * from distributed_logs PREWHERE Alarm_type IN ('{}','{}') AND Timestamp >= date_1 AND Timestamp <= date_2 ORDER BY Timestamp
    """.format(date1_sql, date2_sql, *alarm_types)

    log_data = []
    logger.debug(f'QUERY: {query}')
    t1 = datetime.now()
    try:
        log_data = db_client.execute(query)
    except Exception as e:
        text = f'ERROR: clickhouse connection failed: {e}'
        logger.error(e)
        send_msg(USER_ADMIN_CHAT_ID, text)
        return False
    except KeyboardInterrupt:
        logger.info('\nterminate script process by Ctrl-C\n')
        os._exit(1)

    template_alarm = re.compile(('|'.join(log_template_alarm_list)))
    template_info = re.compile(('|'.join(log_template_info_list)))
    logger.debug(f'Logs Count: {len(log_data)}')
    for item in log_data:
        event_text = item[5]
        if template_alarm.search(event_text):
            parse_event(item)
        if template_info.search(event_text):
            parse_event(item, success_login=True)

    t2 = datetime.now()
    logger.debug(f'SQL Query Time: {str((t2 - t1).total_seconds())}')
    logger.debug(f'{parse_log.__name__}')
    BOT_ALIVE = True
    return True


def parse_event(item, success_login=False):
    logger.debug(f'LOG EVENT: {str(item)}')

    event_login = UNKNOWN_USER
    event_src_ip = '0.0.0.0'
    log_template = str()
    event_create_time = item[1]
    event_host = item[2]
    alarm_type = item[4]
    event_text = item[5]

    for item in LOG_SERVER_TEMPLATES:
        if item in event_text:
            event_text = event_text[event_text.find(item):]

    if alarm_type == ALARM_TYPES[SERVER]:
        secure_log_entry_re = re.compile(r"(?P<log_template>(?:(\D+)|\D+\S+))\s+"
                                         r"for\s+"
                                         r"(?P<illegal_user>(?:((?:illegal|invalid)\ user\s+)|))"
                                         r"(?P<user>(?:(\S+)|))(?:(\s+)|)"
                                         r"from\s+"
                                         r"(?P<src_ip>(?:(\S+)))\s*", re.VERBOSE)

        log_match = secure_log_entry_re.match(event_text)

        if log_match:
            event_login = log_match.groupdict()['user']
            event_src_ip = log_match.groupdict()['src_ip']
            log_template = log_match.groupdict()['log_template']
        else:
            text = f'ERROR: Cannot parse log message: {event_text}'
            logger.error(text)
            send_msg(USER_ADMIN_CHAT_ID, text)

        user: User = USERS.get_user(usertype=SERVER, login=event_login)

        # don't send msg, don't create inc
        if user.chat_id == NOT_SEND:
            return True

        # send msg to chat only, don't create inc (if LOGIN_SUCCESS)
        if success_login:
            # success login to server for unknown user
            if user.login == UNKNOWN_USER:
                msg = MSG_ADMIN_UNKNOWN_LOGIN_SUCCESS
            # success login to server for valid user
            else:
                msg = MSG_USER_LOGIN_SUCCESS

            text = f"{event_host} - {msg}\n\n" \
                   f"Date/Time: {event_create_time.strftime('%d %B - %H:%M:%S')}\n" \
                   f"Source IP: {event_src_ip}\n\n" \
                   f"Log: {event_text}"
            send_msg(USER_ADMIN_CHAT_ID, text)
            return True

        # find similar username
        event_user = parse_username(usertype=SERVER, user_login=event_login)
        # user is unknown ?
        if len(event_user) == 0:
            event_user = UNKNOWN_USER

        log_event = EventLogClass(event_create_time, alarm_type, event_user, event_login, event_host, event_src_ip, event_text)
        logger.debug(f'{parse_event.__name__} {log_event.show()}')

        if CHECK_SERVER_SOURCE_IP_TEMPLATE.lower() in log_template.lower():
            SourceEventsQueue.append(log_event)
        elif CHECK_SERVER_FAILED_LOGIN.lower() in log_template.lower():
            SecureEventsQueue.append(log_event)

    ######
    elif alarm_type == ALARM_TYPES[NETWORK]:
        device_ip = event_text.split(' ')[1]
        try:
            event_hostname = socket.gethostbyaddr(device_ip)[0]
            if event_hostname == device_ip:
                event_hostname = get_host_db('IP', device_ip, 'HostName')
        except socket.herror:
            event_hostname = get_host_db('IP', device_ip, 'HostName')

        tac_log_entry_re = re.compile(r"tac_plus\[\d+]:\s+(?P<ne_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*"
                                      r"(?P<user>(?:(\S+)|))(?:(\s+)|)"
                                      r"(?P<console>(?:(\S+)|))(?:(\s+)|)"
                                      r"(?P<src_ip>(?:(\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))|(\s+\S+))\s+"
                                      r"(?:shell|pap)\s+login\s+failed", re.VERBOSE)

        log_match = tac_log_entry_re.match(event_text)

        if log_match:
            event_login = log_match.groupdict()['user'].strip(' ')
            event_src_ip = log_match.groupdict()['src_ip'].strip(' ')
        else:
            text = 'ERROR: Cannot parse log message: ' + event_text
            logger.error(text)
            send_msg(USER_ADMIN_CHAT_ID, text)
        user: User = USERS.get_user(usertype=NETWORK, login=event_login)

        # don't send msg, don't create inc
        if user.chat_id == NOT_SEND:
            return True

        # find similar username
        event_user = parse_username(usertype=NETWORK, user_login=event_login)

        # user is unknown ?
        if len(event_user) == 0:
            event_user = UNKNOWN_USER

        log_event = EventLogClass(event_create_time, alarm_type, event_user, event_login, event_hostname, event_src_ip,
                                  event_text)

        # if well-known source - don't create Event
        if not is_valid_src_ip(event_src_ip, LIGITIMATE_EXCEPT_SRC):
            SourceEventsQueue.append(log_event)

        logger.debug(f'{parse_event.__name__}. LEN Source Events: {len(SourceEventsQueue)}')
        logger.debug(f'{parse_event.__name__}. TAC Event: {log_event.show()}')
    else:
        return False
    logger.debug('', parse_event.__name__)
    return True


# проверяем ивенты в SOURCE очереди и генерим алармы при не валидном src_ip
def source_queue_checker():
    logger.debug(f'{source_queue_checker.__name__}')
    logger.debug(f'LEN SourceEventsQueue: {len(SourceEventsQueue)}')

    while SourceEventsQueue:
        log_event = SourceEventsQueue.popleft()
        logger.debug(f'{source_queue_checker.__name__}. Username: {log_event.username}')

        if not is_valid_src_ip(log_event.src_ip, SRC_VALID_NETS):
            log_event.descr = MSG_ADMIN_UNKNOWN_SOURCE
            AlarmEventsQueue.append(log_event)
            logger.debug(f'{source_queue_checker.__name__}. LEN ALARM Events: {len(AlarmEventsQueue)}')
            text = '{}: "{}" \n\n{}\nHost: {}\nLogin: {}\n{}'.format(MSG_ADMIN_UNKNOWN_SOURCE, log_event.src_ip,
                                                                     log_event.date.strftime('%d %B - %H:%M:%S'),
                                                                     log_event.host, log_event.login, log_event.text)
            send_msg(USER_ADMIN_CHAT_ID, text)
            check_alarm_queue()

            logger.debug(f'{source_queue_checker.__name__}. Log Event: {log_event.show()}')
        elif log_event.alarm_type == ALARM_TYPES[NETWORK]:
            TacEventsQueue.append(log_event)
            logger.debug(f'{source_queue_checker.__name__}. LEN TAC Events: {len(TacEventsQueue)}')


# проверяем ивенты в SECURE очереди и генерим алармы при превышении пороговых условий
def secure_queue_checker():
    logger.debug(f'{secure_queue_checker.__name__}. LEN SecureEventsQueue: {len(SecureEventsQueue)}')
    login_failed_user_count = {}
    is_user_alarm = dict()

    while SecureEventsQueue:
        log_event = SecureEventsQueue.popleft()
        user_device = (log_event.username, log_event.host)
        logger.debug(f'{secure_queue_checker.__name__}. Username_Device: {user_device}')

        if not is_user_alarm.get(user_device, False):
            if log_event.username not in login_failed_user_count.keys():
                logger.debug(f'{secure_queue_checker.__name__}. Server Failed Users = 1')
                login_failed_user_count[user_device] = 1
            else:
                u = login_failed_user_count[user_device] + 1
                login_failed_user_count[user_device] = u
                logger.debug(f'{secure_queue_checker.__name__}. Server Failed Users = {u}')

            count_user = login_failed_user_count[user_device]

            if log_event.username == UNKNOWN_USER:
                max_attempts = MAX_UNKNOWN_USER_ATTEMPTS_SRV
            else:
                max_attempts = MAX_USER_ATTEMPTS_SRV

            if count_user >= max_attempts:
                alarm_text = '{}: "{}"'.format(MSG_ADMIN_LOGIN_FAILED, log_event.login)
                log_event.descr = alarm_text
                suspicious_user: User = USERS.get_user(usertype=ALARM_TYPES[log_event.alarm_type], login=log_event.login)

                if suspicious_user.login == UNKNOWN_USER:
                    log_event.descr = MSG_ADMIN_UNKNOWN_USER
                    AlarmEventsQueue.append(log_event)
                    text = '{}: "{}" \n\n{}\nHost: {}\nSource IP: {}\n\n{}'.format(MSG_ADMIN_UNKNOWN_USER,
                                                                                   log_event.login,
                                                                                   log_event.date.strftime(
                                                                                       '%d %B - %H:%M:%S'),
                                                                                   log_event.host, log_event.src_ip,
                                                                                   log_event.text)
                    send_msg(USER_ADMIN_CHAT_ID, text)
                    check_alarm_queue()
                else:
                    LogEventsQueue.append(log_event)
                is_user_alarm[user_device] = True
                logger.debug(f'{secure_queue_checker.__name__} Log Event: {log_event.show()}')


# проверяем ивенты в TAC очереди и генерим алармы при превышении пороговых условий
def tac_queue_checker():
    login_failed_user_count = {}
    is_user_alarm = dict()
    logger.debug(f'{tac_queue_checker.__name__}. LEN TacEventsQueue: {len(TacEventsQueue)}')

    while TacEventsQueue:
        log_event = TacEventsQueue.popleft()
        user_device = (log_event.username, log_event.host)
        logger.debug(f'{tac_queue_checker.__name__}. Username: {log_event.username}')

        if not is_user_alarm.get(user_device, False):
            if log_event.username not in login_failed_user_count.keys():
                logger.debug(f'{tac_queue_checker.__name__}. Tacacs Failed Users =  1')
                login_failed_user_count[user_device] = 1
            else:
                u = login_failed_user_count[user_device] + 1
                login_failed_user_count[user_device] = u
                logger.debug(f'{tac_queue_checker.__name__}. Tacacs Failed Users = {u}')

            count_user = login_failed_user_count[user_device]

            if log_event.username == UNKNOWN_USER:
                max_attempts = MAX_UNKNOWN_USER_ATTEMPTS_NET
            else:
                max_attempts = MAX_USER_ATTEMPTS_NET

            if count_user >= max_attempts:
                log_event.descr = MSG_ADMIN_LOGIN_FAILED
                suspicious_user = parse_username(usertype=NETWORK, user_login=log_event.username)
                if suspicious_user in USERS.network.logins:
                    LogEventsQueue.append(log_event)
                else:
                    AlarmEventsQueue.append(log_event)
                    text = '{}: "{}" \n\n{}\nHost: {}\nSource IP: {}\n\n{}'.format(MSG_ADMIN_UNKNOWN_USER,
                                                                                   log_event.login,
                                                                                   log_event.date.strftime(
                                                                                       '%d %B - %H:%M:%S'),
                                                                                   log_event.host, log_event.src_ip,
                                                                                   log_event.text)
                    send_msg(USER_ADMIN_CHAT_ID, text)
                    check_alarm_queue()
                is_user_alarm[user_device] = True
                logger.debug(f'{tac_queue_checker.__name__}. Log Event: {log_event.show()}')


# проверяем на sql инъекции аргументы в команде /reg
def verify_sql_inj(str_from_chat):
    pattern_special_symbols = '[()\[\]\'=,{};"/]'
    if re.search(pattern_special_symbols, str_from_chat):
        return False
    pattern_sql_commands = re.compile(
        '(select|union|where|substr|when|from|limit|then|else|match|true|false|drop|create)')
    if pattern_sql_commands.search(str_from_chat.lower()):
        return False
    return True


def new_user_registration(event, usertype, userlogin):
    global USERS
    if userlogin:
        login_username = userlogin
    else:
        login_username = event.from_chat.split('@')[0].strip()
    logger.info(f'New registration: {login_username}, from: {event.from_chat}')
    new_user = User(usertype, login_username, event.from_chat)
    USERS += new_user
    text = '{}: {} в {} боте'.format(MSG_USER_REG, login_username, usertype)
    send_msg(event.from_chat, text)
    send_msg(USER_ADMIN_CHAT_ID, text)
    write_user_db(new_user)
    logger.info(f'Add new user: {login_username}')


def update_user_registration(event, usertype, userlogin):
    user: User = USERS.get_user(usertype=usertype, chat_id=event.from_chat)
    if userlogin != user:
        logger.info(f'Change registration: {user.login}')
        new_user = User(usertype, userlogin, event.from_chat)
        USERS[user] = userlogin
        write_user_db(new_user, 'update')
        text = '{}: {}'.format(MSG_USER_CHANGE_LOGIN, userlogin)
        send_msg(event.from_chat, text)
        send_msg(USER_ADMIN_CHAT_ID, text)


def bot_cmd_reg_handler(bot, event):
    (cmd, usertype, userlogin) = event.text.split(" ")
    logger.info(f'New user registration: {usertype[1:]} : {userlogin} : {event.from_chat}')
    if not verify_sql_inj(userlogin):
        text = f'From: {event.from_chat}\n Подозрительный запрос на регистрацию: {event.text}'
        send_msg(USER_ADMIN_CHAT_ID, text)
        return False
    chat_username, user_domain = event.from_chat.split('@')
    if user_domain not in MAIL_DOMAIN:
        logger.warning(f'Невалидный домен в chat_id: {chat_username}@{user_domain}')
        return False

    logger.info(f'{usertype} <<>> {event.from_chat} <<>> {USERS.get_user(usertype=usertype, chat_id=event.from_chat)}')

    if USERS.get_user(usertype=usertype, chat_id=event.from_chat) and not userlogin:
        user: User = USERS.get_user(usertype=usertype, chat_id=event.from_chat)
        text = '{}: {}'.format(MSG_USER_EXIST, user.login)
        send_msg(event.from_chat, text)
        send_msg(USER_ADMIN_CHAT_ID, text)
    elif not USERS.get_user(usertype=usertype, chat_id=event.from_chat):
        new_user_registration(event, usertype, userlogin)
    elif userlogin:
        update_user_registration(event, usertype, userlogin)


# обрабатываем команды для бота, вводимые пользователем в чат
def bot_cmd_handler(bot, event):
    global BOT_ALIVE
    CMD_CHAT = namedtuple("CMD_CHAT", "cmd command_body arg1 args_next")

    template_cmd = re.compile(r"/(?P<cmd>(?:(\S+)))\s*"
                              r"(?P<command_body>(?:(\S+|)))\s*"
                              r"(?P<arg1>(?:(\S+|)))\s*"
                              r"(?P<args_next>(?:(\S+|\s+|)+))", re.VERBOSE)
    match = template_cmd.match(event.text)
    if not match:
        return False
    cmd_from_chat = CMD_CHAT(
        cmd=match.groupdict()['cmd'],
        command_body=match.groupdict()['command_body'],
        arg1=match.groupdict()['arg1'],
        args_next=match.groupdict()['args_next']
    )
    logger.debug(f'Command: {format(event.text)}')
    if cmd_from_chat.cmd == "help":
        send_msg(event.from_chat, 'Usage for registration:\n /reg network|server userlogin')
    elif cmd_from_chat.cmd == "show" and cmd_from_chat.arg1 == 'users':
        show_users = ('{0:%s}' % cmd_from_chat.command_body).format(USERS)
        send_msg(USER_ADMIN_CHAT_ID, show_users)
    elif cmd_from_chat.cmd == "ping":
        text = str(BOT_ALIVE)
        send_msg(USER_ADMIN_CHAT_ID, text)
    else:
        BOT_ALIVE = False
        text = 'Бот запущен ...'
        send_msg(event.from_chat, text)
    return True


# если есть Событие - бот пишет юзеру запрос (если юзер известен), или пишет в админскую чат-группу (если юзер Unknown)
def start_dlg():
    logger.debug(f'{start_dlg.__name__}. LEN LogEventsQueue: {len(LogEventsQueue)}')

    while LogEventsQueue:
        log_event : EventLogClass = LogEventsQueue.popleft()
        logger.debug(f'{start_dlg.__name__}. Username: {log_event.username}')
        if log_event.username is not UNKNOWN_USER:
            text = '{}: "{}" \n\n{}\nHost: {}\nSource IP: {}\n\n{}'.format(MSG_USER_PING, log_event.login,
                                                                           log_event.date.strftime('%d %B - %H:%M:%S'),
                                                                           log_event.host, log_event.src_ip,
                                                                           log_event.text)
            u: User = USERS.get_user(ALARM_TYPES[log_event.alarm_type], login=log_event.username)
            logger.debug(f'{start_dlg.__name__}. Username: {u}')
            send_msg(u.chat_id, text, with_buttons=True)
            current_date = datetime.now()
            log_event.set_request(current_date)
            log_event.set_hash(text)
            RequestEventsQueue.append(log_event)
        elif log_event.username is UNKNOWN_USER:
            text = '{}: "{}" \n\n{}\nHost: {}\nSource IP: {}\n\n{}'.format(MSG_ADMIN_UNKNOWN_USER, log_event.login,
                                                                           log_event.date.strftime('%d %B - %H:%M:%S'),
                                                                           log_event.host, log_event.src_ip,
                                                                           log_event.text)
            send_msg(USER_ADMIN_CHAT_ID, text)
            log_event.descr = MSG_ADMIN_UNKNOWN_USER
            current_date = datetime.now()
            log_event.set_request(current_date)
            AlarmEventsQueue.append(log_event)
            check_alarm_queue()
    return True


# обработчик ответов юзера для бота
# если ответ - ДА, ничего не делаем, если НЕТ - создаём jira-инц
def reply_bot(bot, event, hash_log):
    logger.debug(f'{reply_bot.__name__}')
    global BOT_ALIVE
    if event.text.split(' ')[0] in BOT_COMMAND_LIST:
        return False
    if event.text[:1] == '/' and event.text.split(' ')[0] not in BOT_COMMAND_LIST:
        text = "Мне не знакома команда [ " + event.text + " ] ..."
        send_msg(event.from_chat, text)
        return False

    yes_list = ['yes', 'да', 'ага', 'ок', 'ok']
    no_list = ['no', 'нет']

    temp_queue = deque()
    temp_queue.extend(RequestEventsQueue)
    while temp_queue:
        log_event = temp_queue.popleft()
        user: User = USERS.get_user(ALARM_TYPES[log_event.alarm_type], chat_id=event.from_chat)

        if user:
            username = user.login
        else:
            username = UNKNOWN_USER

        logger.debug(f'LEN RequestEventsQueue: {len(RequestEventsQueue)}')
        if username == log_event.username:
            if event.text.lower() in yes_list:
                text = 'ok'
                logger.info(f'Chat: {event.from_chat}. Reply: {text}')
                send_msg(event.from_chat, text)
                log_event.set_reply()
                log_event.set_alarm(False)
                RequestEventsQueue.remove(log_event)
                return True
            elif event.text.lower() in no_list:
                log_event.set_reply()
                log_event.set_alarm(True)
                RequestEventsQueue.remove(log_event)
                log_event.descr = MSG_ADMIN_HACK_LOGIN
                AlarmEventsQueue.append(log_event)
                text = '{}: "{}" \n\n{}\nHost: {}\nSource IP: {}\n{}'.format(MSG_ADMIN_HACK_LOGIN, log_event.username,
                                                                             log_event.date.strftime(
                                                                                 '%d %B - %H:%M:%S'),
                                                                             log_event.host, log_event.src_ip,
                                                                             log_event.text)
                logger.info(text)
                send_msg(event.from_chat, text)
                send_msg(USER_ADMIN_CHAT_ID, text)
                check_alarm_queue()
                return True
            else:
                text = 'Варианты ответа: {} или {}'.format(str(yes_list), str(no_list))
                logger.info(text)
                send_msg(event.from_chat, text)
                return False

    # если боту написали что то ещё (не ответ на запрос)
    user_domain = event.from_chat.split('@')[1].strip()
    if user_domain not in MY_DOMAIN:
        new_username = event.from_chat.split('@')[0].strip()
        logger.warning(f'User is not in MRG/VK domain: {new_username}@{user_domain}')
        return False
    if not USERS.get_user(usertype=NETWORK, chat_id=event.from_chat) \
            and not USERS.get_user(usertype=SERVER, chat_id=event.from_chat):
        text = f'Вы можете зарегистрироваться в боте через команду: /reg {NETWORK}|{SERVER} userlogin'
        secure_bot.send_text(event.from_chat, text)
    return True


# проверяем истёк ли таймаут юзера REPLY_TIMEOUT для ответа на запрос бота,
# если истёк - переносим Событие из очереди Request в очередь Alarm
@_safe_queue
def check_event_timeout():
    temp_queue = deque()
    temp_queue.extend(RequestEventsQueue)
    while temp_queue:
        logger.debug(f'{check_event_timeout.__name__}. LEN RequestEventsQueue: {len(RequestEventsQueue)}')
        log_event = temp_queue.popleft()
        current_date = datetime.now()
        delta_time = current_date - log_event.request_time

        if log_event.request and not log_event.second_request and delta_time.seconds > int(REPLY_TIMEOUT * 0.7):
            text = '{}: "{}" \n\n{}\nHost: {}\nSource IP: {}\n\n{}'.format("RESEND\n" + MSG_USER_PING, log_event.login,
                                                                           log_event.date.strftime('%d %B - %H:%M:%S'),
                                                                           log_event.host, log_event.src_ip,
                                                                           log_event.text)

            u: User = USERS.get_user(ALARM_TYPES[log_event.alarm_type], login=log_event.username)
            send_msg(u.chat_id, text)
            log_event.second_request = True
        elif log_event.request and delta_time.seconds > REPLY_TIMEOUT:
            text = f'{MSG_ADMIN_ALARM_TIMEOUT}.\n\n{log_event.text}'
            u: User = USERS.get_user(ALARM_TYPES[log_event.alarm_type], login=log_event.username)
            send_msg(u.chat_id, text)
            send_msg(USER_ADMIN_CHAT_ID, text)
            RequestEventsQueue.remove(log_event)
            AlarmEventsQueue.append(log_event)
            check_alarm_queue()
    return True


# создаём jira-инциденты для событий в очереди Alarm
# ссылку на jira-инц отправляем юзеру (если он известен), в админскую чат-группу и в Телеграм чат
@_safe_queue
def check_alarm_queue():
    logger.debug(f'{check_alarm_queue.__name__}. LEN AlarmEventsQueue: {len(AlarmEventsQueue)}')

    while AlarmEventsQueue:
        log_event = AlarmEventsQueue.popleft()
        task_id = create_jira_issue(log_event)
        text = f"{MSG_ADMIN_ALARM}: " \
               f"{JIRA_URL}{task_id}\n" \
               f"{log_event.date.strftime('%d %B - %H:%M:%S')}" \
               f"Host: {log_event.host}" \
               f"Source IP: {log_event.src_ip}" \
               f"{log_event.text}"
        if log_event.username is not UNKNOWN_USER:
            u: User = USERS.get_user(ALARM_TYPES[log_event.alarm_type], login=log_event.username)
            send_msg(u.chat_id, text)

        send_msg(USER_ADMIN_CHAT_ID, text)
        text_to_chat = 'Created issue {}{}: {}: User: {}, Host: {}, Source: {}'.format(JIRA_URL, task_id, log_event.descr,
                                                                              log_event.login, log_event.host,
                                                                              log_event.src_ip)
        send_msg(MYTEAM_CRIT_CHAT, text_to_chat)
        logger.info(f'\nCreate Jira Issue: {JIRA_URL}, Task: {task_id}\n')
    return True


def create_jira_issue(log_event):
    user = log_event.login
    if log_event.username is UNKNOWN_USER:
        user = '{} ({})'.format(log_event.login, 'unknown user')
    time_issue_created_iso8601 = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.0+0300")
    header = "{} (user: {})".format(log_event.descr, log_event.login)
    descr = "User: {}\nHostname: {}\nSource: {}\nType: {}\n{}".format(user, log_event.host, log_event.src_ip,
                                                                           log_event.alarm_type,
                                                                           log_event.text)
    priority = {'Blocking': '1', 'Critical': '2', 'Major': '3', 'Minor': '4', 'Trivial': '5'}
    issue_hash = hashlib.md5(header.encode()).hexdigest()

    issue_dict = {
        'project': {'key': 'INC'},
        'priority': {'id': priority[JIRA_PRIORITY]},
        'issuetype': {'name': 'Network'},
        'summary': header,
        'description': descr,
        # Trigger ID
        "customfield_27407": 'Security Incidient',
        "customfield_27404": time_issue_created_iso8601,
        # Hostname
        "customfield_27409": log_event.host,
        "customfield_27408": issue_hash,
        "customfield_27406": 'noc_secure_bot'
    }

    jira_options = {'server': CONFIG['jira']['server']}
    jira_consumer_key = CONFIG['jira']['consumer_key']
    jira_oauth_token_secret = CONFIG['jira']['oauth_token_secret']
    jira_oauth_token = CONFIG['jira']['oauth_token']
    jira_oauth_key_path = CONFIG['jira']['jira_rsa_key_path']
    data = ''

    try:
        with open(jira_oauth_key_path, 'r') as f:
            data = f.read()
    # if unable to read jira oauth rsa key
    except Exception as e:
        text = f'ERROR: {create_jira_issue.__name__}. {e}'
        logger.error(e)
        send_msg(USER_ADMIN_CHAT_ID, text)
        os._exit(-1)

    private_key = data.strip()

    oauth = {'access_token': jira_oauth_token, 'consumer_key': jira_consumer_key,
             'access_token_secret': jira_oauth_token_secret, 'key_cert': private_key}
    try:
        jira = JIRA(options=jira_options, oauth=oauth)
        new_issue = jira.create_issue(fields=issue_dict)
        jira.kill_session()
        logger.debug(f'{create_jira_issue.__name__}')
        return new_issue.key
    # can't access jira server
    except Exception as e:
        text = f'ERROR: {create_jira_issue.__name__}. {e}'
        logger.error(e)
        send_msg(USER_ADMIN_CHAT_ID, text)


# чтение базы зарегистрированных юзеров
def read_user_db(db_table):
    users_db = dict()
    try:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        query = 'SELECT * FROM {}'.format(db_table)
        cursor.execute(query)
        for row in cursor:
            users_db[row[0]] = row[1]
        conn.commit()
        cursor.close()
        conn.close()
    except sqlite3.Error as e:
        text = f'ERROR: cannot get [users] form DB: {e}'
        logger.error(text)
        send_msg(USER_ADMIN_CHAT_ID, text)
        return False
    logger.debug(f'{read_user_db.__name__}')
    return users_db


# запись/обновление юзера в базу зарегистрированных юзеров
def write_user_db(new_user, mode='write'):
    query_db = {'write': 'INSERT INTO %s (%s, %s) VALUES (?, ?)',
                'update': 'UPDATE %s SET %s = ? WHERE %s = ?'}
    chat_id = 'chat_id'
    login = 'login'
    db_table = DB_TABLE[new_user.usertype]
    new_login = new_user.login
    new_chat_id = new_user.chat_id
    try:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        cursor.execute(query_db[mode] % (db_table, login, chat_id), (new_login, new_chat_id,))
        conn.commit()
        cursor.close()
        conn.close()
    except sqlite3.Error as e:
        text = f'{write_user_db.__name__}. {e}'
        logger.error(e)
        send_msg(USER_ADMIN_CHAT_ID, text)
    logger.debug(f'{write_user_db.__name__}')


def read_src_nets():
    logger.info(f'{read_src_nets.__name__}')
    global SRC_VALID_NETS
    try:
        with open(NETWORKS_FILENAME, 'r', encoding='utf8') as f:
            for line in f:
                line = line.split('#', 1)[0].strip()
                if line:
                    SRC_VALID_NETS.append(line)
    except Exception as e:
        text = f'ERROR: cannot read SOURCE NETWORK file: {e}'
        logger.error(e)
        send_msg(USER_ADMIN_CHAT_ID, text)


# MAIN #
def main():
    logger.info('Secure bot started...')
    global USERS, USERS_DEFAULT
    USERS.update_db(NETWORK, USERS_DEFAULT)
    USERS.update_db(SERVER, USERS_DEFAULT)
    USERS.update_db(NETWORK, read_user_db(DB_TABLE_NETWORK))
    USERS.update_db(SERVER, read_user_db(DB_TABLE_SERVER))

    logger.debug(f'User network list: {USERS.get_users(usertype=NETWORK)}')
    logger.debug(f'User server list: {USERS.get_users(usertype=SERVER)}')

    secure_bot.dispatcher.add_handler(CommandHandler(command='reg', callback=bot_cmd_reg_handler))
    secure_bot.dispatcher.add_handler(UnknownCommandHandler(callback=bot_cmd_handler))
    secure_bot.dispatcher.add_handler(MessageHandler(callback=reply_bot))
    secure_bot.dispatcher.add_handler(BotButtonCommandHandler(callback=buttons_answer_cb))
    secure_bot.start_polling()

    db_client = Client(CLICKHOUSE_HOST, port=CLICKHOUSE_PORT)
    query = DBQuery("NetworkHostListWithIP",
                    ['HostName', 'HostState', 'IP', 'HardwareModel_Name', 'NetworkRoles', 'OrgUnitName'],
                    "SELECT * FROM")

    log_template_alarm_list = [
        CHECK_NETWORK_TEMPLATE,
        CHECK_SERVER_FAILED_LOGIN,
        CHECK_SERVER_SOURCE_IP_TEMPLATE]
    log_template_info_list = [CHECK_SERVER_SUCCESS_LOGIN]

    schedule.every(DB_REQUEST_INTERVAL).hours.do(read_src_nets)
    schedule.every(DB_REQUEST_INTERVAL).hours.do(clone_cmdb_to_local)
    schedule.every(DB_REQUEST_INTERVAL).hours.do(read_db, query)
    schedule.every(PARSE_LOG_INTERVAL).seconds.do(parse_log,
                                                  db_client,
                                                  log_template_alarm_list,
                                                  log_template_info_list,
                                                  [ALARM_TYPES[NETWORK], ALARM_TYPES[SERVER]])
    schedule.every(PARSE_LOG_INTERVAL).seconds.do(tac_queue_checker)
    schedule.every(PARSE_LOG_INTERVAL).seconds.do(secure_queue_checker)
    schedule.every(PARSE_LOG_INTERVAL).seconds.do(source_queue_checker)
    schedule.every(PARSE_LOG_INTERVAL).seconds.do(start_dlg)
    schedule.every(PARSE_LOG_INTERVAL).seconds.do(check_event_timeout)
    schedule.every(PARSE_LOG_INTERVAL).seconds.do(check_alarm_queue)
    schedule.run_all()

    try:
        while 1:
            try:
                schedule.run_pending()
            except Exception as e:
                logger.error(f'Unknown Error: {e}')
                os._exit(-1)
            sleep(SCHEDULE_TIMEOUT)
    except KeyboardInterrupt as err:
        db_client.disconnect()
        raise KeyboardInterrupt(err)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as err:
        logger.info('Terminate script process by Ctrl-C')
    except Exception as err:
        logger.critical(f'Unknown exception: {err.with_traceback(sys.exc_info()[2])}')
        os._exit(-1)
