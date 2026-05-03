#%%

import torch
import torch.nn as nn
import json
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

config = TemplateMinerConfig()
config.load("drain3.ini")
miner = TemplateMiner(config=config)

with open("fused_network_process_logs.json", "r") as f:
    data = json.load(f)

#%%
from collections import Counter
from datetime import datetime
import hashlib
import json
def build_session(session_id, logs, miner):
    template_sequence = []
    event_hashes = []
    template_counts = Counter()
    is_suspect_count = 0
    start_time = None
    end_time = None

    entity_id = logs[0]["remote_ip"]  # or session key

    for log in logs:

        # convert JSON → string log
        log_line = (
            f'{log["process_name"]} '
            f'{log["local_ip"]}:{log["local_port"]} -> '
            f'{log["remote_ip"]}:{log["remote_port"]} '
            f'{log["status"]}'
        )

        result = miner.add_log_message(log_line)

        template_id = result["cluster_id"]
        template_sequence.append(template_id)

        template_counts[str(template_id)] += 1

        h = hashlib.md5(log_line.encode()).hexdigest()
        event_hashes.append(h)
        if(log["label"]=="suspicious") :
            is_suspect_count +=  1
        ts = datetime.fromisoformat(log["timestamp"].replace("Z", ""))
        
        if start_time is None:
            start_time = ts
        end_time = ts


    total_suspicion = sum(
        2.0 if t == "unknown.exe" else 1.0
        for t in [l["process_name"] for l in logs]
    )

    return {
        "label" : is_suspect_count >=3,
        "session_id": session_id,
        "entity_id": entity_id,
        "start_time": start_time.isoformat() + "Z",
        "end_time": end_time.isoformat() + "Z",
        "event_count": len(logs),
        "template_counts": dict(template_counts),
        "total_suspicion": total_suspicion,
        "template_sequence": template_sequence,
        "event_hashes": event_hashes
    }

logs = []
for i in range (int(len(data)/10)):

     log = build_session(i, data[i:i+10],miner)
     logs.append(log)
print(logs)

#%%
sequences = [log["template_sequence"] for log in logs]
label = [log["label"] for log in logs]
train_size = int(0.7 * len(sequences))

X_train = sequences[:train_size]
X_test = sequences[train_size:]
Y_train = label[:train_size]
Y_test  = label[train_size:]


X_train = torch.tensor(X_train, dtype=torch.float32)
X_test = torch.tensor(X_test, dtype=torch.float32)
Y_train = torch.tensor(Y_train, dtype=torch.float32)
Y_test = torch.tensor(Y_test, dtype=torch.float32)
X_train = X_train.unsqueeze(-1)
X_test  = X_test.unsqueeze(-1)

class LSTMDetector(nn.Module):

    def __init__(self, input_size=1, hidden_size=64):
        super().__init__()

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=2,
            batch_first=True,
            dropout=0.2
        )

        self.fc = nn.Sequential(
            nn.Linear(hidden_size, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):

        # x shape must be (batch, seq_len, 1)
        out, _ = self.lstm(x)

        out = out[:, -1, :]   # last timestep

        out = self.fc(out)

        return out.squeeze()
input_size = 10

model = LSTMDetector()

criterion = nn.BCELoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=0.001
)



EPOCHS = 100

for epoch in range(EPOCHS):

    model.train()

    optimizer.zero_grad()

    outputs = model(X_train)

    loss = criterion(outputs, Y_train)

    loss.backward()

    optimizer.step()

    print(f"Epoch {epoch+1}/{EPOCHS} | Loss: {loss.item():.4f}")


model.eval()

with torch.no_grad():

    predictions = model(X_test)

    predictions = (predictions > 0.5).float()

    accuracy = (predictions == Y_test).float().mean()

print(f"\nTest Accuracy: {accuracy:.4f}")


torch.save(model.state_dict(), "lstm_model.pth")

print("Model saved!")

#%% 
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import numpy as np
with open("attack_dataset.json", "r") as f:
    logs = json.load(f)
sequences = [log["template_sequence"] for log in logs]
label_map  = {
    "normal" : 0 ,
    "bruteforce" : 1 ,
    "malware_beacon" : 2 ,
    "scan" : 3 ,
    "data_exfiltration" : 4
}

label = [label_map[log["attack_label"]] for log in logs]


X = np.array(sequences)  
y = np.array(label)

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,
    random_state=42
)
model = XGBClassifier(
    n_estimators=200,
    max_depth=5,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss"
)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
model.save_model("xgb_attack_model.json")
print("Accuracy:", acc)