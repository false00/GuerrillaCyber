# Author :: Juan Ortega
# GuerrillaCyber

import subprocess
import traceback
import concurrent.futures

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
import mmap
import contextlib
import xmltodict
from datetime import datetime
from collections import OrderedDict
import json
# TODO - Active Users
# TODO - Processes Opened by User
# TODO - Recent PowerShell Commands
# TODO - Kill Sessions (RDP, SMB, ETC.)
# TODO - Kill Processes
# TODO - Scheduled Events
# TODO - Ingress Traffic


def main():
    win = Windows()
    #result = win.powershell('query user')
    logs, event_ids = win.evtx_parse('C:\\Users\\juanc\\OneDrive\\Desktop\\Demo\\Server\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx')
    result = win.powershell("(quser) -replace '\s{2,}', ',' | ConvertFrom-Csv")

    for i in logs:
        try:
            timestamp = i["System"]["TimeCreated"]["@SystemTime"]
            username = i['UserData']['EventXML']['Param1']

            ##TEST
            username = username.replace('jortega', 'juanc')

            hostname_account_type = i['UserData']['EventXML']['Param2']
            ip_address = i['UserData']['EventXML']['Param3']
            print(timestamp, username, hostname_account_type, ip_address)
        except:
            pass

    # Get User Names returned
    result = result.stdout.decode()
    quser_username = [line for line in result.split('\n') if "USERNAME" in line]
    quser_state = [line for line in result.split('\n') if "STATE" in line]
    quser_idle_time = [line for line in result.split('\n') if "IDLE TIME" in line]
    quser_logon_time = [line for line in result.split('\n') if "LOGON TIME" in line]

    print(quser_username, quser_state, quser_idle_time, quser_logon_time)
    for _ in quser_username:
        print(_)


class Windows:
    log_array = []
    event_ids = []

    @staticmethod
    def powershell(cmd):
        completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
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
            else:
                pass

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


if __name__ == "__main__":
    main()



