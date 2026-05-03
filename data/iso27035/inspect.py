import json

d = json.load(open(r"C:\Users\Youmi\OneDrive\ALLfolders\workflow\data\iso27035\iso_2ec8838d.json"))

print("=" * 65)
print(f"INCIDENT: {d['incident_id'][:8]}")
print(f"Entity:   {d['entity_id']}")
print(f"Status:   {d['overall_status']}")
print(f"Severity: {d['severity']} | Attack: {d['attack_type']}")
print(f"Risk:     {d['risk_score']} ({d['risk_label']})")
print(f"Progress: {d['total_phases_completed']}/{d['total_phases']}")
print("=" * 65)

for phase_name, phase_data in d["phases"].items():
    status = phase_data["status"]
    clause = phase_data["iso_clause"]
    duration = phase_data.get("duration_seconds", 0) or 0
    icon = "✅" if status == "completed" else "⏳" if status == "pending" else "🔄"
    reqs_met = len(phase_data.get("requirements_met", []))
    reqs_total = len(phase_data.get("requirements", []))
    
    print(f"\n{icon} {phase_name}")
    print(f"   Clause: {clause}")
    print(f"   Status: {status} ({duration:.1f}s)")
    print(f"   Compliance: {reqs_met}/{reqs_total} requirements met")
    
    # Show inputs
    inputs = phase_data.get("inputs", {})
    if inputs:
        print(f"   INPUTS:")
        for k, v in list(inputs.items())[:4]:
            print(f"     → {k}: {v}")
    
    # Show outputs
    outputs = phase_data.get("outputs", {})
    if outputs:
        print(f"   OUTPUTS:")
        for k, v in list(outputs.items())[:5]:
            print(f"     → {k}: {v}")
    
    # Sub-phases
    for sub_name, sub_data in phase_data.get("sub_phases", {}).items():
        sub_icon = "✅" if sub_data["status"] == "completed" else "⏳"
        print(f"   {sub_icon} └── {sub_name} [{sub_data['iso_clause']}] — {sub_data['status']}")
        sub_out = sub_data.get("outputs", {})
        if sub_out:
            for k, v in list(sub_out.items())[:3]:
                print(f"         → {k}: {v}")
