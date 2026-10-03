"""Awareness learning center, quizzes and incident guidance (all defensive)."""

LESSONS = {
    "PHISHING": ("Fake messages that trick you into clicking or signing in.",
                 ["Urgent tone", "Sender domain slightly off", "Link text differs from the real destination"],
                 ["Hover to inspect links", "Open the site by typing the address yourself", "Report to your security team"]),
    "MALWARE": ("Software built to harm or spy on a device.",
                ["Unexpected attachments", "Pirated software", "Prompts to enable macros"],
                ["Keep OS and antivirus updated", "Install software only from trusted sources", "Disconnect and report if infected"]),
    "RANSOMWARE": ("Malware that locks files and demands payment.",
                   ["Files suddenly renamed", "Ransom note on screen", "Backups being deleted"],
                   ["Keep offline/immutable backups", "Patch quickly", "Isolate the device and call IR - do not pay on your own"]),
    "CREDENTIAL THREATS": ("Attempts to steal or guess passwords.",
                           ["Many failed logins", "Login alerts from new places", "Reused passwords in breaches"],
                           ["Use a password manager", "Unique passwords", "Turn on MFA"]),
    "WEB THREATS": ("Attacks via websites and web apps.",
                    ["Browser warnings", "Odd redirects", "Unexpected pop-ups"],
                    ["Update browsers", "Heed certificate warnings", "Developers: validate input and patch frameworks"]),
    "NETWORK THREATS": ("Suspicious traffic and scanning against networks.",
                        ["Sweeps across many ports", "Traffic spikes", "Unknown devices"],
                        ["Segment networks", "Close unused ports", "Monitor firewall logs"]),
    "VULNERABILITY EXPOSURE": ("Known software flaws that attackers can use.",
                               ["Outdated software", "Vendor security advisories", "Flaws reported as exploited"],
                               ["Patch by priority (exploited + exposed first)", "Keep an asset inventory", "Use vendor mitigations"]),
    "SOCIAL ENGINEERING": ("Manipulating people rather than systems.",
                           ["Pressure and secrecy", "Requests that bypass process", "Callers claiming authority"],
                           ["Verify via a known channel", "Slow down", "Follow approval procedures"]),
    "DATA EXPOSURE": ("Sensitive data reachable by people who should not see it.",
                      ["Public storage links", "Files shared with 'anyone'", "Data sent to personal email"],
                      ["Least-privilege sharing", "Review public links", "Classify sensitive data"]),
    "ACCOUNT SECURITY": ("Protecting accounts from takeover.",
                         ["Surprise MFA prompts", "Unknown devices in account history", "Password-reset emails you did not request"],
                         ["Deny unexpected MFA prompts", "Use phishing-resistant MFA where possible", "Review sign-in history"]),
}

INCIDENT_GUIDANCE = [
    "1. Stay calm and stop: do not delete anything or 'clean up' yet.",
    "2. Disconnect the affected device from the network (keep it powered on if told to).",
    "3. Report it right away to your IT/security team with what you saw and when.",
    "4. Write down time, message/file names and what you clicked. Screenshots help.",
    "5. Change passwords from a DIFFERENT, clean device if credentials may be exposed.",
    "6. Follow the response team's instructions, then learn from it afterwards.",
]

RECOMMENDED_ACTIONS = {
    "PHISHING": ["Block sender/domain at the mail gateway", "Search mailboxes for similar messages", "Remind users how to report"],
    "MALWARE": ["Check EDR for the hash", "Isolate any matching host", "Review how it arrived"],
    "RANSOMWARE": ["Verify backups are offline and restorable", "Check for shadow-copy deletion", "Escalate to incident response"],
    "CREDENTIAL THREATS": ["Review failed-login trends", "Enforce MFA and lockouts", "Reset exposed credentials"],
    "WEB THREATS": ["Review WAF/web logs", "Patch the exposed application", "Rate-limit abusive sources"],
    "NETWORK THREATS": ["Review firewall logs for the source", "Block at the perimeter if justified", "Check exposed services"],
    "VULNERABILITY EXPOSURE": ["Check asset inventory for the product", "Apply the vendor patch or mitigation", "Prioritise if exploitation is reported"],
    "SOCIAL ENGINEERING": ["Send an awareness notice", "Remind staff of verification steps", "Collect reports"],
    "DATA EXPOSURE": ["Check sharing settings", "Remove public access", "Assess what data was reachable"],
    "ACCOUNT SECURITY": ["Review sign-in logs", "Force re-authentication if needed", "Check for MFA-fatigue patterns"],
}

# (question, options, correct_index, explanation)
QUIZ = [
    ("An email says your account closes in 1 hour unless you click a link. Best response?",
     ["Click quickly", "Open the official site by typing its address", "Forward to coworkers", "Reply with your password"], 1,
     "Urgency is a classic phishing trick. Go to the site yourself."),
    ("Which is the strongest login protection?",
     ["A longer password reused everywhere", "Unique passwords + MFA", "Changing password monthly only", "Writing it on a sticky note"], 1,
     "Unique passwords with MFA stop most account takeovers."),
    ("You get an unexpected MFA prompt you did not trigger. What do you do?",
     ["Approve to stop the alerts", "Deny it and report it", "Ignore it", "Share the code with support"], 1,
     "Unexpected prompts can mean your password is compromised."),
    ("In this dashboard, which level means impact was CONFIRMED?",
     ["OBSERVATION", "INDICATOR", "ALERT", "INCIDENT"], 3,
     "Only INCIDENT means confirmed impact; the others are earlier, less certain stages."),
    ("Which backup practice best helps against ransomware?",
     ["Backups on the same computer", "Offline/immutable, tested backups", "No backups", "Email yourself the files"], 1,
     "Attackers target reachable backups. Keep offline copies and test restores."),
    ("A suspicious attachment arrives from a known colleague. Best step?",
     ["Open it", "Confirm with them using another channel", "Forward it", "Enable macros"], 1,
     "Accounts get hijacked. Verify out-of-band."),
    ("What does a CVE ID identify?",
     ["A malware author", "A publicly catalogued vulnerability", "A phishing email", "A firewall rule"], 1,
     "CVE IDs are catalogue numbers for known vulnerabilities."),
    ("An IOC (e.g., a suspicious domain) appears in a feed. Is it proof you were attacked?",
     ["Yes, always", "No, it needs context and local evidence", "Only if it is long", "Yes if it has numbers"], 1,
     "IOCs are leads. Confirm with your own logs before declaring an incident."),
    ("Which is safest for handling a suspicious link in a report?",
     ["Click to see what happens", "Defang it (hxxp, [.]) and analyze as text", "Paste it into chat apps", "Visit on your work PC"], 1,
     "Defanging prevents accidental clicks."),
    ("Someone calls claiming to be IT and asks for your password. You...",
     ["Give it - they sound official", "Refuse and report", "Give half of it", "Ask them to email it"], 1,
     "Legitimate IT never needs your password."),
]

def awareness_level(pct):
    if pct >= 90: return "Security Champion"
    if pct >= 70: return "Aware"
    if pct >= 50: return "Developing"
    return "Needs Training"
