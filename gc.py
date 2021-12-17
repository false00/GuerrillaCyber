# Author :: Juan Ortega
# GuerrillaCyber

import subprocess
import concurrent.futures
import time
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
import mmap
import contextlib
import xmltodict
from datetime import datetime
from collections import OrderedDict
import json
import sqlite3
from sqlite3 import Error
from base64 import b64encode
import traceback

# TODO - Active Users
# TODO - Processes Opened by User
# TODO - Recent PowerShell Commands
# TODO - Kill Sessions (RDP, SMB, ETC.)
# TODO - Kill Processes
# TODO - Scheduled Events
# TODO - Ingress Traffic
# TODO - Avoid Detection, Avoid Being killed by other processes


def main():
    # Create Database in memory
    create_db = DatabaseTools()
    conn = create_db.create_active_users_db()

    watch = UserWatch()
    while True:
        try:
            watch.windows(conn)
            time.sleep(1)
        except Exception as error:
            message = f'Error | main() | {error}'
            pass


class UserWatch:
    win_conn = []
    quser_conn = []
    evtx_rdp = []

    def windows(self, conn):
        cli_win = CLIWin()

        netstat_results = cli_win.netstat()
        quser_results = cli_win.query_user()

        # check for rdp connections
        for _ in netstat_results:
            source_ip = _[1]
            dest_ip = _[2]

            if ':3389' in source_ip:
                if _ not in self.win_conn:
                    self.win_conn.append(_)
                    message = f'UserWatch.windows | Network | Connected | Ingress (Incoming) | {_[0]}, SIP:{_[1]}, DIP:{_[2]}, ' \
                              f'State: {_[3]},  PID: {_[4]}'
                    print(message)

            if ':3389' in dest_ip:
                if _ not in self.win_conn:
                    self.win_conn.append(_)
                    message = f'UserWatch.windows | Network | Connected | Egress (Outgoing) | {_[0]}, SIP:{_[1]}, DIP:{_[2]}, ' \
                              f'State: {_[3]},  PID: {_[4]}'
                    print(message)

        # check for disconnected rdp connections
        for _ in self.win_conn:
            source_ip = _[1]
            dest_ip = _[2]

            # The connection no longer shows up in netstat
            if _ not in netstat_results:
                if ':3389' in source_ip:
                        message = f'UserWatch.windows | Network | Disconnected | Ingress (Incoming) | {_[0]}, SIP:{_[1]}, DIP:{_[2]}, ' \
                                  f'State: DISCONNECTED,  PID: {_[4]}'
                        print(message)
                if ':3389' in dest_ip:
                        message = f'UserWatch.windows | Network | Disconnected | Egress (Outgoing) | {_[0]}, SIP:{_[1]}, DIP:{_[2]}, ' \
                                  f'State: DISCONNECTED,  PID: {_[4]}'
                        print(message)
                # Remove from win_conn
                self.win_conn.remove(_)

        # check for user sessions
        for _ in quser_results:
            if _ not in self.quser_conn:
                self.quser_conn.append(_)
                message = f'UserWatch.windows | User Session | Username: {_[0]}, Type: {_[1]}, State: {_[2]}, ' \
                          f'Idle Time: {_[3]}, LogonTime: {_[4]}'
                print(message)

        # check for disconnected user sessions
        for _ in self.quser_conn:
            # The connection no longer shows up in quser
            if _ not in quser_results:
                # Remove from quser_conn
                self.quser_conn.remove(_)

        term_serv_remote_conn = 'C:\\Windows\\System32\\winevt\\Logs\\' \
                                'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx'

        win = Windows()

        logs, event_ids = win.evtx_parse(term_serv_remote_conn)

        for i in logs:
            try:
                event_id = i['Event']['System']['EventID']['#text']
                timestamp = i["System"]["TimeCreated"]["@SystemTime"]
                username = i['UserData']['EventXML']['Param1']
                hostname_account_type = i['UserData']['EventXML']['Param2']
                ip_address = i['UserData']['EventXML']['Param3']

                entry = [event_id, timestamp, username, hostname_account_type, ip_address]

                if entry not in self.evtx_rdp:
                    self.evtx_rdp.append(entry)

                    message = f'UserWatch.windows | EVTX | Forensics | RDP CONN | event_id: {event_id}, timestamp: {timestamp}, ' \
                              f'username: {username}, hostname_account_type: {hostname_account_type}, ' \
                              f'ip_address: {ip_address}'
                    print(message)
            except:
                pass


class CLIWin:

    @staticmethod
    def query_user():
        win = Windows()

        cmd = r"(quser) -replace '\s{2,}', ',' | ConvertFrom-Csv"
        result = win.powershell(cmd)

        # quser stout
        result = result.stdout.decode()

        # UserName
        quser_username = [line for line in result.split('\n') if "USERNAME" in line]
        for i, username in enumerate(quser_username):
            quser_username[i] = username.split(':')[1].replace('>', '').strip()

        # Session Name
        quser_sessionname = [line for line in result.split('\n') if 'SESSIONNAME' in line]
        for i, sessionname in enumerate(quser_sessionname):
            quser_sessionname[i] = sessionname.split(':')[1].strip()

        # Query State
        quser_state = [line for line in result.split('\n') if "STATE" in line]
        for i, state in enumerate(quser_state):
            quser_state[i] = state.split(':')[1].replace('>', '').strip()

        # Idle Time
        quser_idle_time = [line for line in result.split('\n') if "IDLE TIME" in line]
        for i, idle_time in enumerate(quser_idle_time):
            quser_idle_time[i] = idle_time.split(':')[1].replace('>', '').strip()

        # Logon Time
        quser_logon_time = [line for line in result.split('\n') if "LOGON TIME" in line]
        for i, logon_time in enumerate(quser_logon_time):
            try:
                quser_logon_time[i] = logon_time.split(': ')[1].replace('>', '').strip()
                quser_logon_time[i] = datetime.strptime(quser_logon_time[i], "%m/%d/%Y %H:%M %p")
                quser_logon_time[i] = str(quser_logon_time[i].isoformat())
            except:
                quser_logon_time[i] = ''

        # Refactor Array
        quser_array = []
        for (a, b, c, d, e) in zip(quser_username, quser_sessionname, quser_state, quser_idle_time, quser_logon_time):
            entry = []
            entry.extend([a, b, c, d, e])
            quser_array.append(entry)

        return quser_array

    @staticmethod
    def netstat():
        win = Windows()
        cmd = r'(netstat -bano | Select -skip 2) -join "`n" -split "(?= [TU][CD]P\s+(?:\d+\.|\[\w*:\w*:))" | ' \
              r'ForEach-Object {$_.trim() -replace "`n"," " -replace "\s{2,}",","} | ConvertFrom-Csv'

        cmd = cmd

        result = win.powershell(cmd)

        # netstat stout
        result = result.stdout.decode()

        # Proto
        proto = [line for line in result.split('\n') if "Proto" in line]
        for i, p in enumerate(proto):
            proto[i] = p.split(' : ')[1].strip()

        # Local Address
        local_address = [line for line in result.split('\n') if 'Local' in line]
        for i, local in enumerate(local_address):
            local_address[i] = local.split(' : ')[1].strip()

        # Foreign Address
        foreign_address = [line for line in result.split('\n') if "Foreign" in line]
        for i, foreign in enumerate(foreign_address):
            foreign_address[i] = foreign.split(' : ')[1].strip()

        # State
        state = [line for line in result.split('\n') if "State" in line]
        for i, s in enumerate(state):
            state[i] = s.split(' : ')[1].strip()

        # PID
        pid = [line for line in result.split('\n') if "PID" in line]
        for i, p in enumerate(pid):
            pid[i] = p.split(' : ')[1].strip()

        # Refactor Array
        netconns = []
        for (a, b, c, d, e) in zip(proto, local_address, foreign_address, state, pid):
            entry = []
            entry.extend([a, b, c, d, e])
            netconns.append(entry)

        return netconns


class Windows:
    log_array = []
    event_ids = []

    @staticmethod
    def powershell(cmd):
        completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
        return completed

    @staticmethod
    def powershell_b64(cmd):
        # Encode commands like so: cat raw.txt | iconv --to-code UTF-16LE | base64 -w 0
        cmd = b64encode(cmd.encode('UTF-16LE'))
        completed = subprocess.run(["powershell", "-EncodedCommand", cmd], capture_output=True)
        return completed

    def evtx_parse(self, log_path):
        with open(log_path) as infile:
            with contextlib.closing(mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                fh = FileHeader(buf, 0x0)
                data = ""

                # Multithreading to increase parsing speed
                with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                    futures = []

                    for xml, record in evtx_file_xml_view(fh):
                        futures.append(executor.submit(self.parse_xml, xml=xml, record=record))

                    for future in concurrent.futures.as_completed(futures):
                        future.result()

        return self.log_array, self.event_ids

    def parse_xml(self, xml, record):
        try:
            contains_event_data = False
            log_line = xmltodict.parse(xml)

            # Format the date field
            date = log_line.get("Event").get("System").get("TimeCreated").get("@SystemTime")
            if "." not in str(date):
                date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
            else:
                date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S.%f")
            log_line['@timestamp'] = str(date.isoformat())
            log_line["Event"]["System"]["TimeCreated"]["@SystemTime"] = str(date.isoformat())

            # Process the data field to be searchable
            data = ""
            if log_line.get("Event") is not None:
                data = log_line.get("Event")

                if log_line.get("Event").get("EventData") is not None:
                    data = log_line.get("Event").get("EventData")
                    if log_line.get("Event").get("EventData").get("Data") is not None:
                        data = log_line.get("Event").get("EventData").get("Data")
                        if isinstance(data, list):
                            contains_event_data = True
                            data_vals = {}
                            for dataitem in data:
                                try:
                                    if dataitem.get("@Name") is not None:
                                        data_vals[str(dataitem.get("@Name"))] = str(
                                            str(dataitem.get("#text")))
                                except:
                                    pass
                            log_line["Event"]["EventData"]["Data"] = data_vals
                        else:
                            if isinstance(data, OrderedDict):
                                log_line["Event"]["EventData"]["RawData"] = json.dumps(data)
                            else:
                                log_line["Event"]["EventData"]["RawData"] = str(data)
                            del log_line["Event"]["EventData"]["Data"]
                    else:
                        if isinstance(data, OrderedDict):
                            log_line["Event"]["RawData"] = json.dumps(data)
                        else:
                            log_line["Event"]["RawData"] = str(data)
                        del log_line["Event"]["EventData"]
                else:
                    if isinstance(data, OrderedDict):
                        log_line = dict(data)
                    else:
                        log_line["RawData"] = str(data)
                        del log_line["Event"]

            try:
                # Whole Message
                event_data = json.loads(json.dumps(log_line))
                self.log_array.append(event_data)
            except:
                pass

            try:
                # Event IDs
                event_id = event_data['Event']['System']['EventID']['#text']
                self.event_ids.append(event_id)
            except:
                pass

        except:
            pass


class DatabaseTools:

    @staticmethod
    def create_connection(db_file):
        """ create a database connection to the SQLite database
            specified by db_file
        :param db_file: database file
        :return: Connection object or None
        """
        conn = None
        try:
            conn = sqlite3.connect(db_file)
            return conn
        except Error as e:
            print(e)

        return conn

    @staticmethod
    def create_table(conn, create_table_sql):
        """ create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        try:
            c = conn.cursor()
            c.execute(create_table_sql)
        except Error as e:
            print(e)

    def create_active_users_db(self):
        # create a database connection
        database = ':memory:'
        conn = self.create_connection(database)
        # Quser:  ['jortega', 'rdp-tcp#27', 'Active', '.', '2021-11-26T11:49:00'] | Remote Connection Logs: 2021-11-29T02:53:18.033215 jortega None 192.168.1.233
        active_users_sql = """ CREATE TABLE IF NOT EXISTS quser (
                                                id integer PRIMARY KEY,
                                                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                                                username text,
                                                sessionname text,
                                                state text,
                                                idletime text,
                                                logontime DATETIME 
                                            ); """

        evtx_rdp_operational_sql = """ CREATE TABLE IF NOT EXISTS evtx_rdp_ops (
                                                id integer PRIMARY KEY,
                                                timestamp DATETIME,
                                                username text,
                                                hostname text,
                                                ip text
                                            ); """
        # create tables
        if conn is not None:
            # create active users table
            self.create_table(conn, active_users_sql)

            # create evtx TerminalServices-RemoteConnectionManager%4Operational table
            self.create_table(conn, evtx_rdp_operational_sql)
        else:
            print("Error! cannot create the database connection.")

        return conn


if __name__ == "__main__":
    main()



