# 🎨 Document 4: Terminal UI Mocks (mocks.md)

**Requirement:** Output must match these visuals closely using `tabled` for lists and standard formatting for dashboard headers.

### 1. Daemon Startup
```terminal
$ keeper start
🔒 Enter Keeper Vault Password: ************
✅ Daemon started. PID: 8821. Socket: ~/.keeper/keeper.sock
$ _
```

### 2. Quick Capture (CLI)
```terminal
$ keeper note "Fix auth bug" @work !p1 ^today
[✓] Saved to @work (ID: 142)
$ _
```

### 3. Retrieval (CLI)
```terminal
$ keeper get @work
+-----+--------+---------------------------+-----------+------------+
| ID  | Bucket | Content                   | Priority  | Due        |
+-----+--------+---------------------------+-----------+------------+
| 142 | @work  | Fix auth bug              | 🚨 P1     | Today      |
| 130 | @work  | Prepare slides            | ⭐ P2     | 2025-12-01 |
+-----+--------+---------------------------+-----------+------------+
$ _
```

### 4. Interactive Dashboard (REPL Entry)
Displayed immediately upon running `keeper`.

```terminal
$ keeper
  _  __                             
 | |/ /___ ___ _ __   ___ _ __  
 |   // _ \ _ \ '_ \ / _ \ '__|     v0.1.0
 |_|\_\___|\___| .__/ \___|_|    ⚡ Daemon Connected
               |_|

 🚨 URGENT FOCUS (Top P1s) __________________________________
 +-----+-----------------------------+--------+------------+
 | ID  | Task                        | Context| Due        |
 +-----+-----------------------------+--------+------------+
 | 142 | Fix the auth bug on staging | @work  | Today      |
 | 99  | Pay electricity bill        | @home  | Today      |
 | 105 | Renew domain name           | @side  | Tomorrow   |
 +-----+-----------------------------+--------+------------+

 📅 APPROACHING (Due Tomorrow) ______________________________
 * [⭐ P2] Prepare slides for Q3 review (@work)

 📊 QUICK STATS _____________________________________________
 Open: 15 | Done Today: 3 | P1: 3 | Notes: 42

keeper> _
```
