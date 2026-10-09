import os, re, time, secrets, hashlib, sqlite3
from functools import wraps
from flask import Flask, request, jsonify, g

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
DB_PATH = os.environ.get("SCENELINK_DB", os.path.join(os.getcwd(), "scenelink.sqlite3"))
ONLINE_SECONDS = 45
MAX_PLAYERS = 5

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, nickname TEXT NOT NULL COLLATE NOCASE UNIQUE,
 token_hash TEXT NOT NULL UNIQUE, created_at REAL NOT NULL, last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS friends (
 id INTEGER PRIMARY KEY AUTOINCREMENT, requester_id TEXT NOT NULL, target_id TEXT NOT NULL,
 status TEXT NOT NULL, created_at REAL NOT NULL, UNIQUE(requester_id,target_id)
);
CREATE TABLE IF NOT EXISTS parties (
 code TEXT PRIMARY KEY, owner_id TEXT NOT NULL, project TEXT NOT NULL DEFAULT '',
 password_hash TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, closed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS members (
 party_code TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, joined_at REAL NOT NULL,
 PRIMARY KEY(party_code,user_id), UNIQUE(user_id)
);
CREATE TABLE IF NOT EXISTS join_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT, party_code TEXT NOT NULL, user_id TEXT NOT NULL,
 status TEXT NOT NULL, created_at REAL NOT NULL, UNIQUE(party_code,user_id)
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, party_code TEXT NOT NULL, user_id TEXT NOT NULL,
 nickname TEXT NOT NULL, text TEXT NOT NULL, created_at REAL NOT NULL
);
"""

def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    con = db()
    try:
        con.executescript(SCHEMA)
        con.commit()
    finally:
        con.close()
init_db()

def error(message, status=400):
    return jsonify({"error": message}), status

def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def auth_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return error("Authentication required. Register from the client.", 401)
        con = db()
        try:
            row = con.execute("SELECT * FROM users WHERE token_hash=?", (digest(auth[7:].strip()),)).fetchone()
        finally:
            con.close()
        if not row:
            return error("Session token is invalid. Reconnect from the client.", 401)
        g.user = dict(row)
        return fn(*args, **kwargs)
    return wrapped

def valid_name(value):
    name = str(value or "").strip()
    if not 3 <= len(name) <= 20 or not re.match(r"^[A-Za-z0-9 _-]+$", name):
        return None
    return name

def party_public(con, code, owner_requests=None):
    p = con.execute("SELECT * FROM parties WHERE code=? AND closed=0", (code,)).fetchone()
    if not p:
        return None
    owner = con.execute("SELECT nickname FROM users WHERE id=?", (p["owner_id"],)).fetchone()
    ms = con.execute("SELECT m.user_id,m.role,u.nickname,u.last_seen FROM members m JOIN users u ON u.id=m.user_id WHERE m.party_code=? ORDER BY m.joined_at", (code,)).fetchall()
    players = [{"id":m["user_id"],"name":m["nickname"],"role":m["role"],
                "host":m["user_id"] == p["owner_id"],"online":time.time()-float(m["last_seen"]) < ONLINE_SECONDS} for m in ms]
    result = {"code":p["code"],"owner":owner["nickname"] if owner else "Host","project":p["project"],
              "player_count":len(players),"max_players":MAX_PLAYERS,"players":players,
              "has_password":bool(p["password_hash"]),"join_requests":[]}
    if owner_requests == p["owner_id"]:
        rr=con.execute("SELECT jr.id,u.nickname FROM join_requests jr JOIN users u ON u.id=jr.user_id WHERE jr.party_code=? AND jr.status='pending' ORDER BY jr.created_at",(code,)).fetchall()
        result["join_requests"]=[{"id":r["id"],"name":r["nickname"]} for r in rr]
    return result

@app.get("/")
def health():
    return jsonify({"service":"SceneLink Lite Online Service","status":"ok","version":1,
      "features":["presence","friends","party listings","join requests","roles","party text chat"],
      "not_included":["voice chat","image transfer","DMX sync","viewport markers"]})

@app.post("/api/register")
def register():
    data=request.get_json(silent=True) or {}
    name=valid_name(data.get("nickname"))
    if not name: return error("Nickname must be 3-20 characters using letters, numbers, spaces, _ or -.")
    uid=secrets.token_hex(16); token=secrets.token_urlsafe(32); now=time.time()
    con=db()
    try:
        con.execute("INSERT INTO users(id,nickname,token_hash,created_at,last_seen) VALUES(?,?,?,?,?)",(uid,name,digest(token),now,now))
        con.commit()
    except sqlite3.IntegrityError:
        return error("That nickname is already registered. Choose another nickname.",409)
    finally: con.close()
    return jsonify({"user_id":uid,"token":token,"nickname":name,"message":"Registered and connected."}),201

@app.post("/api/heartbeat")
@auth_required
def heartbeat():
    con=db()
    try:
        con.execute("UPDATE users SET last_seen=? WHERE id=?",(time.time(),g.user["id"]))
        row=con.execute("SELECT party_code FROM members WHERE user_id=?",(g.user["id"],)).fetchone()
        con.commit()
        return jsonify({"ok":True,"nickname":g.user["nickname"],"online":True,"party_code":row["party_code"] if row else None})
    finally: con.close()

@app.get("/api/community")
@auth_required
def community():
    tab=request.args.get("tab","everyone").lower()
    search=request.args.get("search","").lower()[:40]
    con=db()
    try:
        me=g.user["id"]
        if tab=="friends":
            rows=con.execute("SELECT u.id,u.nickname FROM friends f JOIN users u ON u.id=CASE WHEN f.requester_id=? THEN f.target_id ELSE f.requester_id END WHERE (f.requester_id=? OR f.target_id=?) AND f.status='accepted' ORDER BY u.nickname",(me,me,me)).fetchall()
            friends=[]
            for r in rows:
                if search and search not in r["nickname"].lower(): continue
                member=con.execute("SELECT party_code FROM members WHERE user_id=?",(r["id"],)).fetchone()
                last=con.execute("SELECT last_seen FROM users WHERE id=?",(r["id"],)).fetchone()["last_seen"]
                friends.append({"id":r["id"],"nickname":r["nickname"],"online":time.time()-float(last)<ONLINE_SECONDS,"party_code":member["party_code"] if member else None})
            ins=con.execute("SELECT f.id,u.nickname FROM friends f JOIN users u ON u.id=f.requester_id WHERE f.target_id=? AND f.status='pending' ORDER BY f.created_at",(me,)).fetchall()
            outs=con.execute("SELECT f.id,u.nickname FROM friends f JOIN users u ON u.id=f.target_id WHERE f.requester_id=? AND f.status='pending' ORDER BY f.created_at",(me,)).fetchall()
            return jsonify({"friends":friends,"incoming_requests":[{"id":r["id"],"nickname":r["nickname"]} for r in ins],"outgoing_requests":[{"id":r["id"],"nickname":r["nickname"]} for r in outs]})
        if tab=="parties":
            codes=con.execute("SELECT code FROM parties WHERE closed=0 ORDER BY created_at DESC LIMIT 100").fetchall()
            out=[]
            for row in codes:
                p=party_public(con,row["code"])
                if not p: continue
                if search and search not in (p["owner"]+" "+p["code"]+" "+p["project"]).lower(): continue
                r=con.execute("SELECT status FROM join_requests WHERE party_code=? AND user_id=?",(p["code"],me)).fetchone()
                p["request_pending"]=bool(r and r["status"]=="pending")
                out.append(p)
            return jsonify({"parties":out})
        rows=con.execute("SELECT id,nickname,last_seen FROM users ORDER BY nickname LIMIT 200").fetchall()
        accepted=set(r[0] for r in con.execute("SELECT CASE WHEN requester_id=? THEN target_id ELSE requester_id END FROM friends WHERE (requester_id=? OR target_id=?) AND status='accepted'",(me,me,me)).fetchall())
        users=[]
        for r in rows:
            if r["id"]==me or (search and search not in r["nickname"].lower()): continue
            mem=con.execute("SELECT party_code FROM members WHERE user_id=?",(r["id"],)).fetchone()
            users.append({"id":r["id"],"nickname":r["nickname"],"online":time.time()-float(r["last_seen"])<ONLINE_SECONDS,
                          "party_code":mem["party_code"] if mem else None,"is_friend":r["id"] in accepted})
        return jsonify({"users":users})
    finally: con.close()

@app.post("/api/friends/request")
@auth_required
def friends_request():
    data=request.get_json(silent=True) or {}; name=valid_name(data.get("nickname"))
    if not name: return error("Enter a valid nickname.")
    con=db()
    try:
        target=con.execute("SELECT id FROM users WHERE nickname=? COLLATE NOCASE",(name,)).fetchone()
        if not target: return error("No registered player has that nickname.",404)
        if target["id"]==g.user["id"]: return error("You cannot add yourself.")
        pair=con.execute("SELECT * FROM friends WHERE requester_id=? AND target_id=?",(g.user["id"],target["id"])).fetchone()
        rev=con.execute("SELECT * FROM friends WHERE requester_id=? AND target_id=?",(target["id"],g.user["id"])).fetchone()
        if pair and pair["status"] in ("pending","accepted") or rev and rev["status"]=="accepted":
            return error("A request or friendship already exists.",409)
        if rev and rev["status"]=="pending":
            con.execute("UPDATE friends SET status='accepted' WHERE id=?",(rev["id"],)); con.commit()
            return jsonify({"message":"Friend request accepted automatically because they already requested you."})
        con.execute("INSERT INTO friends(requester_id,target_id,status,created_at) VALUES(?,?,?,?)",(g.user["id"],target["id"],"pending",time.time())); con.commit()
        return jsonify({"message":"Friend request sent."}),201
    except sqlite3.IntegrityError:
        return error("Friend request already exists.",409)
    finally: con.close()

@app.post("/api/friends/respond")
@auth_required
def friends_respond():
    data=request.get_json(silent=True) or {}
    try: rid=int(data.get("request_id"))
    except Exception: return error("Invalid request id.")
    action=data.get("action")
    if action not in ("accept","reject"): return error("Action must be accept or reject.")
    con=db()
    try:
        r=con.execute("SELECT * FROM friends WHERE id=? AND target_id=? AND status='pending'",(rid,g.user["id"])).fetchone()
        if not r: return error("Friend request not found.",404)
        if action=="accept": con.execute("UPDATE friends SET status='accepted' WHERE id=?",(rid,))
        else: con.execute("DELETE FROM friends WHERE id=?",(rid,))
        con.commit(); return jsonify({"message":"Friend request %s."%("accepted" if action=="accept" else "rejected")})
    finally: con.close()

@app.delete("/api/friends/<path:nickname>")
@auth_required
def friends_remove(nickname):
    con=db()
    try:
        u=con.execute("SELECT id FROM users WHERE nickname=? COLLATE NOCASE",(nickname,)).fetchone()
        if u:
            con.execute("DELETE FROM friends WHERE (requester_id=? AND target_id=?) OR (requester_id=? AND target_id=?)",(g.user["id"],u["id"],u["id"],g.user["id"]))
            con.commit()
        return jsonify({"message":"Friend removed."})
    finally: con.close()

@app.post("/api/parties")
@auth_required
def party_create():
    data=request.get_json(silent=True) or {}
    project=str(data.get("project",""))[:180]; password=str(data.get("password",""))[:100]
    con=db()
    try:
        old=con.execute("SELECT party_code FROM members WHERE user_id=?",(g.user["id"],)).fetchone()
        if old: return error("Leave your current party before creating another.",409)
        code="SLM-"+secrets.token_hex(3).upper()
        ph=digest(password) if password else ""
        con.execute("INSERT INTO parties(code,owner_id,project,password_hash,created_at,closed) VALUES(?,?,?,?,?,0)",(code,g.user["id"],project,ph,time.time()))
        con.execute("INSERT INTO members(party_code,user_id,role,joined_at) VALUES(?,?,?,?)",(code,g.user["id"],"Owner",time.time()))
        con.commit(); return jsonify({"party":party_public(con,code,owner_requests=g.user["id"]),"message":"Party created."}),201
    finally: con.close()

@app.post("/api/parties/<code>/requests")
@auth_required
def party_request(code):
    data=request.get_json(silent=True) or {}; password=str(data.get("password",""))[:100]
    con=db()
    try:
        p=con.execute("SELECT * FROM parties WHERE code=? AND closed=0",(code,)).fetchone()
        if not p: return error("Party not found.",404)
        if p["owner_id"]==g.user["id"]: return error("You are already the host.",409)
        if con.execute("SELECT 1 FROM members WHERE user_id=?",(g.user["id"],)).fetchone(): return error("Leave your current party first.",409)
        if con.execute("SELECT COUNT(*) FROM members WHERE party_code=?",(code,)).fetchone()[0]>=MAX_PLAYERS: return error("Party is full.",409)
        if p["password_hash"] and digest(password)!=p["password_hash"]: return error("Incorrect party password.",403)
        old=con.execute("SELECT id,status FROM join_requests WHERE party_code=? AND user_id=?",(code,g.user["id"])).fetchone()
        if old and old["status"]=="pending": return jsonify({"message":"Your request is already pending."})
        if old: con.execute("UPDATE join_requests SET status='pending',created_at=? WHERE id=?",(time.time(),old["id"]))
        else: con.execute("INSERT INTO join_requests(party_code,user_id,status,created_at) VALUES(?,?,?,?)",(code,g.user["id"],"pending",time.time()))
        con.commit(); return jsonify({"message":"Join request sent. The host must accept it."}),201
    finally: con.close()

@app.get("/api/parties/<code>")
@auth_required
def party_details(code):
    con=db()
    try:
        if not con.execute("SELECT 1 FROM members WHERE party_code=? AND user_id=?",(code,g.user["id"])).fetchone():
            return error("You are not a member of this party.",403)
        p=party_public(con,code,owner_requests=g.user["id"])
        if not p: return error("Party not found.",404)
        return jsonify({"party":p})
    finally: con.close()

@app.post("/api/parties/<code>/requests/<int:request_id>")
@auth_required
def party_decide(code,request_id):
    action=(request.get_json(silent=True) or {}).get("action")
    if action not in ("accept","reject"): return error("Action must be accept or reject.")
    con=db()
    try:
        p=con.execute("SELECT owner_id FROM parties WHERE code=? AND closed=0",(code,)).fetchone()
        if not p: return error("Party not found.",404)
        if p["owner_id"]!=g.user["id"]: return error("Only the owner can decide join requests.",403)
        r=con.execute("SELECT * FROM join_requests WHERE id=? AND party_code=? AND status='pending'",(request_id,code)).fetchone()
        if not r: return error("Join request not found.",404)
        if action=="accept":
            if con.execute("SELECT COUNT(*) FROM members WHERE party_code=?",(code,)).fetchone()[0]>=MAX_PLAYERS: return error("Party is full.",409)
            if con.execute("SELECT 1 FROM members WHERE user_id=?",(r["user_id"],)).fetchone(): return error("Player already belongs to a party.",409)
            con.execute("INSERT INTO members(party_code,user_id,role,joined_at) VALUES(?,?,?,?)",(code,r["user_id"],"Director",time.time()))
            con.execute("UPDATE join_requests SET status='accepted' WHERE id=?",(request_id,))
        else: con.execute("UPDATE join_requests SET status='rejected' WHERE id=?",(request_id,))
        con.commit(); return jsonify({"message":"Join request %s."%("accepted" if action=="accept" else "rejected")})
    finally: con.close()

@app.put("/api/parties/<code>/roles")
@auth_required
def party_role(code):
    data=request.get_json(silent=True) or {}; nickname=valid_name(data.get("nickname")); role=data.get("role")
    if role not in ("Director","Animator"): return error("Choose Director or Animator.")
    con=db()
    try:
        p=con.execute("SELECT owner_id FROM parties WHERE code=? AND closed=0",(code,)).fetchone()
        if not p: return error("Party not found.",404)
        if p["owner_id"]!=g.user["id"]: return error("Only the owner can assign roles.",403)
        u=con.execute("SELECT id FROM users WHERE nickname=? COLLATE NOCASE",(nickname,)).fetchone()
        if not u: return error("Player not found.",404)
        if u["id"]==g.user["id"]: return error("Owner role cannot be changed.",403)
        cur=con.execute("UPDATE members SET role=? WHERE party_code=? AND user_id=?",(role,code,u["id"]))
        if cur.rowcount==0: return error("Player is not in this party.",404)
        con.commit(); return jsonify({"message":"Role updated."})
    finally: con.close()

@app.post("/api/parties/<code>/chat")
@auth_required
def party_chat_send(code):
    text=str((request.get_json(silent=True) or {}).get("text","")).strip()
    if not text: return error("Message cannot be empty.")
    if len(text)>400: return error("Message is limited to 400 characters.")
    con=db()
    try:
        if not con.execute("SELECT 1 FROM members WHERE party_code=? AND user_id=?",(code,g.user["id"])).fetchone(): return error("You are not in this party.",403)
        con.execute("INSERT INTO messages(party_code,user_id,nickname,text,created_at) VALUES(?,?,?,?,?)",(code,g.user["id"],g.user["nickname"],text,time.time()))
        con.commit(); return jsonify({"message":"Sent."}),201
    finally: con.close()

@app.get("/api/parties/<code>/chat")
@auth_required
def party_chat_read(code):
    try: since=int(request.args.get("since",0))
    except Exception: since=0
    con=db()
    try:
        if not con.execute("SELECT 1 FROM members WHERE party_code=? AND user_id=?",(code,g.user["id"])).fetchone(): return error("You are not in this party.",403)
        rows=con.execute("SELECT id,nickname,text,created_at FROM messages WHERE party_code=? AND id>? ORDER BY id LIMIT 100",(code,since)).fetchall()
        return jsonify({"messages":[{"id":r["id"],"nickname":r["nickname"],"text":r["text"],"created_at":r["created_at"]} for r in rows]})
    finally: con.close()

@app.delete("/api/parties/<code>")
@auth_required
def party_leave(code):
    con=db()
    try:
        p=con.execute("SELECT owner_id FROM parties WHERE code=? AND closed=0",(code,)).fetchone()
        if not p: return jsonify({"message":"Party already closed."})
        if not con.execute("SELECT 1 FROM members WHERE party_code=? AND user_id=?",(code,g.user["id"])).fetchone(): return error("You are not in this party.",403)
        if p["owner_id"]==g.user["id"]:
            con.execute("UPDATE parties SET closed=1 WHERE code=?",(code,))
            con.execute("DELETE FROM members WHERE party_code=?",(code,))
            con.execute("UPDATE join_requests SET status='closed' WHERE party_code=? AND status='pending'",(code,))
            con.commit(); return jsonify({"message":"Party closed."})
        con.execute("DELETE FROM members WHERE party_code=? AND user_id=?",(code,g.user["id"]))
        con.commit(); return jsonify({"message":"Left party."})
    finally: con.close()

@app.errorhandler(404)
def missing(_): return jsonify({"error":"Endpoint not found."}),404
@app.errorhandler(413)
def too_large(_): return jsonify({"error":"Request too large."}),413

if __name__=="__main__":
    app.run(host="127.0.0.1",port=int(os.environ.get("PORT","8000")),debug=False)
