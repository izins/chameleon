#%%

import json

def make_phrase (logs):
    to_parse_log = []
    for log in logs :
    
       phrase= (
    f'{log["process_name"]}' 
    f'connection {log["local_ip"]}:{log["local_port"]} -> '
    f'{log["remote_ip"]} : {log["remote_port"]} '
    f'status={log["status"]} pid={log["pid"]}'
)
       to_parse_log.append( phrase)
    return  to_parse_log

with open("fused_network_process_logs.json", "r") as f:
    data = json.load(f)
    data = make_phrase(data)
    print(data)
with open("data.json", "w") as f:
    json.dump(data, f, indent=2)
