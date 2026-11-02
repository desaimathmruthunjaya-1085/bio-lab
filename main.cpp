// ============================================================
//  Bio Laboratory - Access Verification System
//  Alliance University | Micro-Project (C++ core + web front end)
//
//  Data structures (all hand-written, no STL containers for the core):
//    1. Hash table with chaining ........ researcher authentication
//    2. Circular queue .................. normal access requests (FIFO)
//    3. Stack ........................... emergency overrides (LIFO)
//    4. Binary search tree .............. zone hierarchy + permissions
//    5. Merge sort + binary search ...... audit log
//
//  The browser UI in /public talks to this program through a small
//  JSON API. The HTTP server below is plain sockets, written by hand.
// ============================================================
// Build (no external libraries, no threads - works on old MinGW too):
//   Windows : g++ -std=c++11 main.cpp -o labgate.exe -lws2_32
//   Linux/Mac: g++ -std=c++11 main.cpp -o labgate
#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET sock_t;
#define CLOSESOCK closesocket
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_t;
#define INVALID_SOCKET (-1)
#define CLOSESOCK close
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

// ---------- small helpers ----------------------------------
static string jesc(const string &s) {
    string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else if ((unsigned char)c < 0x20) o += ' ';
        else o += c;
    }
    return o;
}
static string q(const string &s) { return "\"" + jesc(s) + "\""; }
static string clockOf(time_t t) {
    char buf[16];
    struct tm *tmv = localtime(&t);
    strftime(buf, sizeof buf, "%H:%M:%S", tmv);
    return buf;
}
static string itos(long long v) { ostringstream o; o << v; return o.str(); }
static int toInt(const string &s, int def) {
    if (s.empty()) return def;
    char *end;
    long v = strtol(s.c_str(), &end, 10);
    return *end ? def : (int)v;
}
static string fakeCode(const string &id, unsigned salt) {  // simulated credential
    unsigned h = salt;
    for (char c : id) h = h * 131u + (unsigned char)c;
    char buf[16];
    sprintf(buf, "%04X", h % 65536u);
    return buf;
}

// Passwords are never stored. Only a salted hash is kept (FNV-1a, demo grade).
static string passHash(const string &pw) {
    unsigned long long h = 1469598103934665603ULL;
    string salted = "BioLaboratory:" + pw;
    for (size_t i = 0; i < salted.size(); i++) { h ^= (unsigned char)salted[i]; h *= 1099511628211ULL; }
    ostringstream o;
    o << hex << h;
    return o.str();
}

// ============================================================
//  1. RESEARCHER + HASH TABLE (chaining with linked lists)
// ============================================================
struct Researcher {
    string id, name, role, status;  // status: Authorized | Restricted | Revoked
    string fingerprint, nfc;        // fingerprint: simulated "FP-xxxx" or a real Windows Hello id "WA:..."
    string passHash;                // salted hash of the password
};

struct HNode {
    Researcher data;
    HNode *next;
};

class HashTable {
    static const int B = 3;  // few buckets on purpose, so collisions (chaining) are visible
    HNode *bucket[B];
    int count;

public:
    HashTable() : count(0) { for (int i = 0; i < B; i++) bucket[i] = nullptr; }
    ~HashTable() { clear(); }
    void clear() {
        for (int i = 0; i < B; i++)
            while (bucket[i]) { HNode *n = bucket[i]; bucket[i] = n->next; delete n; }
        count = 0;
    }
    HashTable(const HashTable &) = delete;
    HashTable &operator=(const HashTable &) = delete;

    static int buckets() { return B; }
    int size() const { return count; }
    int hashOf(const string &id) const {
        unsigned long h = 0;
        for (char c : id) h = h * 31 + (unsigned char)c;
        return (int)(h % B);
    }
    bool insert(const Researcher &r) {
        if (r.id.empty()) return false;
        int b = hashOf(r.id);
        int probes;
        if (find(r.id, probes)) return false;  // duplicate ID
        HNode *tail = bucket[b];
        HNode *n = new HNode{r, nullptr};
        if (!tail) bucket[b] = n;
        else { while (tail->next) tail = tail->next; tail->next = n; }
        count++;
        return true;
    }
    Researcher *find(const string &id, int &probes) {
        probes = 0;
        for (HNode *n = bucket[hashOf(id)]; n; n = n->next) {
            probes++;
            if (n->data.id == id) return &n->data;
        }
        return nullptr;
    }
    template <class F> void each(F f) {  // f(bucketIndex, positionInChain, Researcher&)
        for (int b = 0; b < B; b++) {
            int pos = 0;
            for (HNode *n = bucket[b]; n; n = n->next) f(b, pos++, n->data);
        }
    }
    vector<string> chainIds(int b) {
        vector<string> v;
        for (HNode *n = bucket[b]; n; n = n->next) v.push_back(n->data.id);
        return v;
    }
};

// ============================================================
//  2. CIRCULAR QUEUE (normal requests, FIFO)
// ============================================================
struct Request {
    int ticket = 0;
    string id, method, credential;
    int zone = 1;
};

class CircularQueue {
public:
    static const int SIZE = 8;

private:
    Request items[SIZE];
    int front, rear;

public:
    CircularQueue() : front(-1), rear(-1) {}
    void reset() { front = rear = -1; }
    int getFront() const { return front; }
    int getRear() const { return rear; }
    int count() const { return front == -1 ? 0 : ((rear - front + SIZE) % SIZE) + 1; }
    bool occupied(int i) const { return front != -1 && ((i - front + SIZE) % SIZE) < count(); }
    const Request &at(int i) const { return items[i]; }
    bool enqueue(const Request &r) {
        if ((rear + 1) % SIZE == front) return false;  // full
        if (front == -1) front = 0;
        rear = (rear + 1) % SIZE;
        items[rear] = r;
        return true;
    }
    bool dequeue(Request &out) {
        if (front == -1) return false;  // empty
        out = items[front];
        if (front == rear) front = rear = -1;
        else front = (front + 1) % SIZE;
        return true;
    }
};

// ============================================================
//  3. STACK (emergency commands, LIFO)
// ============================================================
struct Command {
    int ticket = 0;
    string type, target;  // LOCKDOWN | LIFT_LOCKDOWN | REVOKE | RESTORE | ALERT
};

class EmergencyStack {
public:
    static const int SIZE = 5;

private:
    Command items[SIZE];
    int top;

public:
    EmergencyStack() : top(-1) {}
    void reset() { top = -1; }
    int getTop() const { return top; }
    bool empty() const { return top == -1; }
    const Command &at(int i) const { return items[i]; }
    bool push(const Command &c) {
        if (top == SIZE - 1) return false;
        items[++top] = c;
        return true;
    }
    bool pop(Command &out) {
        if (top == -1) return false;
        out = items[top--];
        return true;
    }
};

// ============================================================
//  4. ZONE TREE (binary search tree keyed by security level)
// ============================================================
struct Zone {
    int level;
    string name;
    set<string> allowed;  // researcher IDs with permission
    Zone *left, *right;
    Zone(int l, const string &n) : level(l), name(n), left(nullptr), right(nullptr) {}
};

class ZoneTree {
    Zone *root;
    static Zone *insert(Zone *n, int level, const string &name) {
        if (!n) return new Zone(level, name);
        if (level < n->level) n->left = insert(n->left, level, name);
        else if (level > n->level) n->right = insert(n->right, level, name);
        return n;
    }
    static void destroy(Zone *n) { if (n) { destroy(n->left); destroy(n->right); delete n; } }
    static void inorder(Zone *n, vector<Zone *> &out) {
        if (!n) return;
        inorder(n->left, out); out.push_back(n); inorder(n->right, out);
    }
    static void preorder(Zone *n, vector<Zone *> &out) {  // root first: re-inserting in this order rebuilds the same tree
        if (!n) return;
        out.push_back(n); preorder(n->left, out); preorder(n->right, out);
    }
    static string toJson(Zone *n) {
        if (!n) return "null";
        string s = "{\"level\":" + itos(n->level) + ",\"name\":" + q(n->name) + ",\"allowed\":[";
        bool first = true;
        for (const string &id : n->allowed) { if (!first) s += ","; s += q(id); first = false; }
        return s + "],\"left\":" + toJson(n->left) + ",\"right\":" + toJson(n->right) + "}";
    }

public:
    ZoneTree() : root(nullptr) {}
    ~ZoneTree() { destroy(root); }
    void add(int level, const string &name) { root = insert(root, level, name); }
    Zone *find(int level) {  // O(log n) on a balanced tree
        Zone *n = root;
        while (n && n->level != level) n = level < n->level ? n->left : n->right;
        return n;
    }
    vector<Zone *> all() { vector<Zone *> v; inorder(root, v); return v; }
    vector<Zone *> preorderList() { vector<Zone *> v; preorder(root, v); return v; }
    void clear() { destroy(root); root = nullptr; }
    string json() { return toJson(root); }
};

// ============================================================
//  5. AUDIT LOG (merge sort + binary search)
// ============================================================
struct LogEntry {
    int seq = 0;
    time_t at = 0;
    string id, name, zone, result, reason, kind;  // kind: ACCESS | EMERGENCY
    int severity = 0;                              // 0 granted, 1 denied, 2 emergency
};

template <class Less>
void mergeSort(vector<LogEntry> &v, int l, int r, Less less) {  // sorts v[l..r)
    if (r - l < 2) return;
    int m = (l + r) / 2;
    mergeSort(v, l, m, less);
    mergeSort(v, m, r, less);
    vector<LogEntry> tmp;
    int i = l, j = m;
    while (i < m && j < r) tmp.push_back(less(v[j], v[i]) ? v[j++] : v[i++]);  // stable
    while (i < m) tmp.push_back(v[i++]);
    while (j < r) tmp.push_back(v[j++]);
    for (int k = 0; k < (int)tmp.size(); k++) v[l + k] = tmp[k];
}
static bool byTime(const LogEntry &a, const LogEntry &b) { return a.at != b.at ? a.at < b.at : a.seq < b.seq; }
static bool byId(const LogEntry &a, const LogEntry &b) { return a.id != b.id ? a.id < b.id : byTime(a, b); }
static bool bySeverity(const LogEntry &a, const LogEntry &b) { return a.severity != b.severity ? a.severity > b.severity : byTime(a, b); }

static string logJson(const LogEntry &e) {
    return "{\"seq\":" + itos(e.seq) + ",\"time\":" + q(clockOf(e.at)) + ",\"id\":" + q(e.id) +
           ",\"name\":" + q(e.name) + ",\"zone\":" + q(e.zone) + ",\"result\":" + q(e.result) +
           ",\"reason\":" + q(e.reason) + ",\"kind\":" + q(e.kind) + ",\"severity\":" + itos(e.severity) + "}";
}
static string logsJson(const vector<LogEntry> &v) {
    string s = "[";
    for (size_t i = 0; i < v.size(); i++) { if (i) s += ","; s += logJson(v[i]); }
    return s + "]";
}

// ============================================================
//  LAB STATE (everything the controller owns)
// ============================================================
static HashTable researchers;
static CircularQueue requests;
static EmergencyStack emergencies;
static ZoneTree zones;
static vector<LogEntry> auditLog;
static bool lockdown = false;
static int nextTicket = 1, nextSeq = 1;

static void addLog(time_t at, const string &id, const string &name, const string &zone,
                   const string &result, const string &reason, const string &kind, int sev) {
    LogEntry e;
    e.seq = nextSeq++; e.at = at; e.id = id; e.name = name; e.zone = zone;
    e.result = result; e.reason = reason; e.kind = kind; e.severity = sev;
    auditLog.push_back(e);
}

static Researcher makeResearcher(const string &id, const string &name, const string &role, const string &status, const string &password) {
    Researcher r;
    r.id = id; r.name = name; r.role = role; r.status = status;
    r.passHash = passHash(password);
    r.fingerprint = "FP-" + fakeCode(id, 7);
    r.nfc = "NFC-" + fakeCode(id, 13);
    return r;
}

static void seed() {
    researchers.insert(makeResearcher("101", "Rahul", "Lab Technician", "Authorized", "rahul@101"));
    researchers.insert(makeResearcher("102", "Ananya", "Senior Scientist", "Authorized", "ananya@102"));
    researchers.insert(makeResearcher("103", "Kiran", "Guest Researcher", "Restricted", "kiran@103"));
    researchers.insert(makeResearcher("104", "Priya", "Security Officer", "Authorized", "priya@104"));
    researchers.insert(makeResearcher("105", "Arun", "Research Intern", "Restricted", "arun@105"));

    zones.add(2, "Testing Area");
    zones.add(1, "General Lab");
    zones.add(3, "Research Area");
    zones.add(4, "High Security Zone");
    for (const char *id : {"101", "102", "103", "104", "105"}) zones.find(1)->allowed.insert(id);
    for (const char *id : {"101", "102", "104"}) zones.find(2)->allowed.insert(id);
    for (const char *id : {"102", "103", "104"}) zones.find(3)->allowed.insert(id);
    for (const char *id : {"102", "104"}) zones.find(4)->allowed.insert(id);

    time_t n = time(nullptr);  // a little history so sorting/searching has something to show
    addLog(n - 3600, "101", "Rahul", "Testing Area", "GRANTED", "Verified and permitted", "ACCESS", 0);
    addLog(n - 3300, "103", "Kiran", "Research Area", "DENIED", "Researcher status: Restricted", "ACCESS", 1);
    addLog(n - 2900, "102", "Ananya", "High Security Zone", "GRANTED", "Verified and permitted", "ACCESS", 0);
    addLog(n - 2500, "999", "Unknown", "General Lab", "DENIED", "Researcher ID not registered", "ACCESS", 1);
    addLog(n - 1800, "101", "Rahul", "High Security Zone", "DENIED", "No permission for High Security Zone", "ACCESS", 1);
    addLog(n - 1200, "104", "Priya", "General Lab", "GRANTED", "Verified and permitted", "ACCESS", 0);
    addLog(n - 600, "102", "Ananya", "Research Area", "GRANTED", "Verified and permitted", "ACCESS", 0);
}

// ============================================================
//  SAVING AND LOADING (one text file, labdata.txt)
//  Saved: researchers (with password hashes), zones and permissions, the whole audit log,
//         lockdown state, pending emergency commands and the ticket counters.
//  Not saved: requests waiting in the queue (they carry typed credentials).
// ============================================================
static const char *DATA_FILE = "labdata.txt";

static string cleanField(string s) {
    for (size_t i = 0; i < s.size(); i++) if (s[i] == '\t' || s[i] == '\n' || s[i] == '\r') s[i] = ' ';
    return s;
}
static vector<string> splitTabs(const string &line) {
    vector<string> v;
    size_t st = 0;
    for (;;) {
        size_t t = line.find('\t', st);
        if (t == string::npos) { v.push_back(line.substr(st)); break; }
        v.push_back(line.substr(st, t - st));
        st = t + 1;
    }
    return v;
}
static void resetAll() {
    researchers.clear(); zones.clear(); requests.reset(); emergencies.reset();
    auditLog.clear(); lockdown = false; nextTicket = 1; nextSeq = 1;
}
static bool saveAll() {
    string tmp = string(DATA_FILE) + ".tmp";
    {
        ofstream f(tmp.c_str());
        if (!f) return false;
        f << "BIO1\n";
        f << "G\t" << (lockdown ? 1 : 0) << "\t" << nextTicket << "\t" << nextSeq << "\n";
        researchers.each([&](int, int, Researcher &r) {
            f << "R\t" << cleanField(r.id) << "\t" << cleanField(r.name) << "\t" << cleanField(r.role) << "\t" << cleanField(r.status)
              << "\t" << cleanField(r.fingerprint) << "\t" << cleanField(r.nfc) << "\t" << r.passHash << "\n";
        });
        vector<Zone *> zl = zones.preorderList();
        for (size_t i = 0; i < zl.size(); i++) {
            f << "Z\t" << zl[i]->level << "\t" << cleanField(zl[i]->name) << "\t";
            bool first = true;
            for (set<string>::const_iterator it = zl[i]->allowed.begin(); it != zl[i]->allowed.end(); ++it) {
                if (!first) f << ",";
                f << cleanField(*it);
                first = false;
            }
            f << "\n";
        }
        for (size_t i = 0; i < auditLog.size(); i++) {
            const LogEntry &e = auditLog[i];
            f << "L\t" << e.seq << "\t" << (long long)e.at << "\t" << cleanField(e.id) << "\t" << cleanField(e.name) << "\t"
              << cleanField(e.zone) << "\t" << cleanField(e.result) << "\t" << cleanField(e.reason) << "\t" << cleanField(e.kind)
              << "\t" << e.severity << "\n";
        }
        for (int i = 0; i <= emergencies.getTop(); i++) {
            const Command &c = emergencies.at(i);
            f << "S\t" << c.ticket << "\t" << cleanField(c.type) << "\t" << cleanField(c.target) << "\n";
        }
        if (!f) return false;
    }
    remove(DATA_FILE);  // Windows cannot rename over an existing file
    return rename(tmp.c_str(), DATA_FILE) == 0;
}
// returns 1 = loaded, 0 = no file yet, -1 = file damaged, -2 = older version of the file
static int loadAll() {
    ifstream f(DATA_FILE);
    if (!f) return 0;
    string line;
    if (!getline(f, line)) return -1;
    if (line.compare(0, 4, "VBL1") == 0) return -2;  // written by an older version (different password salt)
    if (line.compare(0, 4, "BIO1") != 0) return -1;
    resetAll();
    bool ok = true;
    while (ok && getline(f, line)) {
        if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
        if (line.empty()) continue;
        vector<string> t = splitTabs(line);
        if (t[0] == "G" && t.size() == 4) {
            lockdown = t[1] == "1"; nextTicket = toInt(t[2], 1); nextSeq = toInt(t[3], 1);
        } else if (t[0] == "R" && t.size() == 8) {
            Researcher r;
            r.id = t[1]; r.name = t[2]; r.role = t[3]; r.status = t[4]; r.fingerprint = t[5]; r.nfc = t[6]; r.passHash = t[7];
            ok = researchers.insert(r);
        } else if (t[0] == "Z" && t.size() == 4) {
            int level = toInt(t[1], 0);
            zones.add(level, t[2]);
            Zone *z = zones.find(level);
            if (!z) { ok = false; break; }
            stringstream ss(t[3]);
            string id;
            while (getline(ss, id, ',')) if (!id.empty()) z->allowed.insert(id);
        } else if (t[0] == "L" && t.size() == 10) {
            LogEntry e;
            e.seq = toInt(t[1], 0); e.at = (time_t)strtol(t[2].c_str(), NULL, 10); e.id = t[3]; e.name = t[4]; e.zone = t[5];
            e.result = t[6]; e.reason = t[7]; e.kind = t[8]; e.severity = toInt(t[9], 0);
            auditLog.push_back(e);
        } else if (t[0] == "S" && t.size() == 4) {
            Command c;
            c.ticket = toInt(t[1], 0); c.type = t[2]; c.target = t[3];
            ok = emergencies.push(c);
        } else ok = false;
    }
    return ok ? 1 : -1;
}

// ---------- processing -------------------------------------
static string stepsJson(const vector<string> &st) {
    string s = "[";
    for (size_t i = 0; i < st.size(); i++) { if (i) s += ","; s += q(st[i]); }
    return s + "]";
}

static string processEmergency(const Command &c) {
    vector<string> steps;
    string title, detail;
    steps.push_back("Stack top popped: " + c.type + (c.target.empty() ? "" : " " + c.target));
    if (c.type == "LOCKDOWN") {
        lockdown = true; title = "Lockdown started"; detail = "All access is denied until the lockdown is lifted";
    } else if (c.type == "LIFT_LOCKDOWN") {
        lockdown = false; title = "Lockdown lifted"; detail = "Normal access can resume";
    } else if (c.type == "REVOKE" || c.type == "RESTORE") {
        int probes;
        Researcher *r = researchers.find(c.target, probes);
        steps.push_back("Hash lookup for " + c.target + ": " + itos(probes) + " probe(s)");
        if (!r) { title = "Target not found"; detail = "No researcher with ID " + c.target; }
        else {
            r->status = c.type == "REVOKE" ? "Revoked" : "Authorized";
            title = c.type == "REVOKE" ? "Access revoked" : "Access restored";
            detail = r->name + " is now " + r->status;
        }
    } else {
        title = "Security alert raised"; detail = c.target.empty() ? "Security staff notified" : "Security staff notified: " + c.target;
    }
    steps.push_back(detail);
    string who = (c.type == "REVOKE" || c.type == "RESTORE") ? c.target : "-";
    addLog(time(nullptr), who, "System", "All zones", "EXECUTED", detail, "EMERGENCY", 2);
    return "{\"kind\":\"emergency\",\"ticket\":" + itos(c.ticket) + ",\"outcome\":\"emergency\",\"title\":" + q(title) + ",\"detail\":" + q(detail) +
           ",\"steps\":" + stepsJson(steps) + "}";
}

static string processRequest(const Request &req) {
    vector<string> steps;
    string name = "Unknown", zoneName = "Zone " + itos(req.zone);
    string reason;
    bool granted = false;

    Zone *z = zones.find(req.zone);
    if (z) zoneName = z->name;
    steps.push_back("Dequeued ticket #" + itos(req.ticket) + ": ID " + req.id + " wants " + zoneName);

    if (lockdown) {
        int p0;
        Researcher *known = researchers.find(req.id, p0);  // only to name the person in the log
        if (known) name = known->name;
        reason = "Lab is in lockdown";
        steps.push_back("Lockdown is active, so the request is denied before verification");
    } else {
        int probes;
        Researcher *r = researchers.find(req.id, probes);
        steps.push_back("Hash table: bucket " + itos(researchers.hashOf(req.id)) + ", " + itos(probes) + " probe(s)");
        if (!r) {
            reason = "Researcher ID not registered";
            steps.push_back("No match in the chain");
        } else {
            name = r->name;
            steps.push_back("Found " + r->name + " (" + r->role + ")");
            string label = req.method == "nfc" ? "NFC card" : (req.method == "password" ? "Password" : "Fingerprint");
            bool match;
            if (req.method == "password") match = passHash(req.credential) == r->passHash;
            else if (req.method == "nfc") match = req.credential == r->nfc;
            else match = req.credential == r->fingerprint;
            if (!match) {
                reason = label + " does not match";
                steps.push_back(label + " check failed");
            } else {
                steps.push_back(label + " matched");
                if (r->status != "Authorized") {
                    reason = "Researcher status: " + r->status;
                    steps.push_back("Status is " + r->status);
                } else {
                    steps.push_back("Status is Authorized");
                    if (!z) {
                        reason = "Unknown zone";
                        steps.push_back("Zone tree has no node for level " + itos(req.zone));
                    } else if (z->allowed.count(r->id)) {
                        granted = true;
                        reason = "Verified and permitted";
                        steps.push_back("Zone tree: " + z->name + " (level " + itos(z->level) + ") lists " + r->name);
                    } else {
                        reason = "No permission for " + z->name;
                        steps.push_back("Zone tree: " + z->name + " does not list " + r->name);
                    }
                }
            }
        }
    }
    addLog(time(nullptr), req.id, name, zoneName, granted ? "GRANTED" : "DENIED", reason, "ACCESS", granted ? 0 : 1);
    return "{\"kind\":\"access\",\"ticket\":" + itos(req.ticket) + ",\"name\":" + q(name) + ",\"zone\":" + q(zoneName) + ",\"reason\":" + q(reason) + ",\"outcome\":" + q(granted ? "granted" : "denied") + ",\"title\":" +
           q(granted ? "Access granted" : "Access denied") + ",\"detail\":" + q(name + " to " + zoneName + ": " + reason) +
           ",\"steps\":" + stepsJson(steps) + "}";
}

// ---------- JSON builders ----------------------------------
static string stateJson() {
    string s = "{\"lab\":\"Bio Laboratory\",\"lockdown\":" + string(lockdown ? "true" : "false");
    s += ",\"bucketCount\":" + itos(HashTable::buckets()) + ",\"researchers\":[";
    bool first = true;
    researchers.each([&](int b, int pos, Researcher &r) {
        if (!first) s += ",";
        first = false;
        s += "{\"id\":" + q(r.id) + ",\"name\":" + q(r.name) + ",\"role\":" + q(r.role) + ",\"status\":" + q(r.status) +
             ",\"fingerprint\":" + q(r.fingerprint) + ",\"nfc\":" + q(r.nfc) + ",\"fpReal\":" + string(r.fingerprint.compare(0, 3, "WA:") == 0 ? "true" : "false") + ",\"bucket\":" + itos(b) +
             ",\"pos\":" + itos(pos) + "}";
    });
    s += "],\"queue\":{\"size\":" + itos(CircularQueue::SIZE) + ",\"front\":" + itos(requests.getFront()) +
         ",\"rear\":" + itos(requests.getRear()) + ",\"count\":" + itos(requests.count()) + ",\"slots\":[";
    for (int i = 0; i < CircularQueue::SIZE; i++) {
        if (i) s += ",";
        if (requests.occupied(i)) {
            const Request &r = requests.at(i);
            Zone *z = zones.find(r.zone);
            s += "{\"filled\":true,\"ticket\":" + itos(r.ticket) + ",\"id\":" + q(r.id) + ",\"method\":" + q(r.method) +
                 ",\"zone\":" + q(z ? z->name : "?") + "}";
        } else s += "{\"filled\":false}";
    }
    s += "]},\"stack\":{\"size\":" + itos(EmergencyStack::SIZE) + ",\"top\":" + itos(emergencies.getTop()) + ",\"items\":[";
    for (int i = 0; i <= emergencies.getTop(); i++) {
        if (i) s += ",";
        const Command &c = emergencies.at(i);
        s += "{\"ticket\":" + itos(c.ticket) + ",\"type\":" + q(c.type) + ",\"target\":" + q(c.target) + "}";
    }
    s += "]},\"zones\":" + zones.json() + ",\"zoneList\":[";
    vector<Zone *> zl = zones.all();
    for (size_t i = 0; i < zl.size(); i++) {
        if (i) s += ",";
        s += "{\"level\":" + itos(zl[i]->level) + ",\"name\":" + q(zl[i]->name) + "}";
    }
    s += "],\"logs\":" + logsJson(auditLog) + "}";
    return s;
}

static string msg(bool ok, const string &m) { return "{\"ok\":" + string(ok ? "true" : "false") + ",\"message\":" + q(m) + "}"; }

// ============================================================
//  API ROUTES  (each returns a JSON string)
// ============================================================
typedef map<string, string> Params;
static string P(const Params &p, const string &k) {
    Params::const_iterator it = p.find(k);
    return it == p.end() ? string() : it->second;
}

// Steps 3-4 of the algorithm: receive a request, put it in the circular queue
static string apiRequest(const Params &p) {
    Request r;
    r.id = P(p, "id");
    string m = P(p, "method");
    r.method = m == "nfc" ? "nfc" : (m == "fingerprint" ? "fingerprint" : "password");
    r.credential = P(p, "credential");
    r.zone = toInt(P(p, "zone"), 1);
    if (r.id.empty()) return msg(false, "Enter a researcher ID first");
    r.ticket = nextTicket;
    if (!requests.enqueue(r)) return msg(false, "Queue is full. Process a request first");
    nextTicket++;
    return "{\"ok\":true,\"ticket\":" + itos(r.ticket) + ",\"message\":" + q("Ticket #" + itos(r.ticket) + " joined the queue") + "}";
}

// Emergency commands go on the stack
static string apiEmergency(const Params &p) {
    Command c;
    c.type = P(p, "type");
    c.target = P(p, "target");
    bool needsTarget = c.type == "REVOKE" || c.type == "RESTORE";
    if (needsTarget && c.target.empty()) return msg(false, "This command needs a researcher ID");
    if (!needsTarget) c.target = "";
    c.ticket = nextTicket;
    if (!emergencies.push(c)) return msg(false, "Emergency stack is full");
    nextTicket++;
    return msg(true, "Emergency command pushed on the stack");
}

// Steps 5-9: emergencies first, otherwise the next normal request
static string apiProcess() {
    Command c;
    Request r;
    if (emergencies.pop(c)) return "{\"ok\":true,\"result\":" + processEmergency(c) + "}";
    if (requests.dequeue(r)) return "{\"ok\":true,\"result\":" + processRequest(r) + "}";
    return msg(false, "Nothing is waiting");
}

// A real door unit decides at once: queue the request, then run everything ahead of it
// (emergencies first, then older tickets) until this person's ticket has been decided.
static string apiDoor(const Params &p) {
    Request r;
    r.id = P(p, "id");
    string m = P(p, "method");
    r.method = m == "nfc" ? "nfc" : (m == "fingerprint" ? "fingerprint" : "password");
    r.credential = P(p, "credential");
    r.zone = toInt(P(p, "zone"), 1);
    if (r.id.empty()) return msg(false, "Enter your ID");
    r.ticket = nextTicket;
    if (!requests.enqueue(r)) return msg(false, "Device is busy. Try again");
    nextTicket++;
    for (int guard = 0; guard < 100; guard++) {
        Command c;
        Request next;
        if (emergencies.pop(c)) { processEmergency(c); continue; }
        if (!requests.dequeue(next)) break;
        string res = processRequest(next);
        if (next.ticket == r.ticket) return "{\"ok\":true,\"result\":" + res + "}";
    }
    return msg(false, "Could not complete the request");
}

// The emergency button on the door device: push a security alert, then pop it at once.
// Last in, first out means we pop exactly the alert we pushed; older commands stay waiting.
static string apiAlert(const Params &p) {
    Command c;
    c.type = "ALERT";
    string id = P(p, "id");
    Zone *z = zones.find(toInt(P(p, "zone"), 0));
    string where = id.empty() ? "" : "ID " + id;
    if (z) where += (where.empty() ? "" : " at ") + z->name;
    c.target = where.empty() ? "the door device" : where;
    c.ticket = nextTicket++;
    if (P(p, "pending") == "1") {                 // door in "send to admin" mode: leave it waiting on the stack
        if (emergencies.push(c)) return msg(true, "Alert is waiting on the emergency stack for security");
        processEmergency(c);                      // stack is full, but an alarm must never be lost
        return msg(true, "Security alert raised. Security has been notified");
    }
    if (emergencies.push(c)) {
        Command top;
        emergencies.pop(top);
        processEmergency(top);
    } else {
        processEmergency(c);  // stack is full, but an alarm must never be lost
    }
    return msg(true, "Security alert raised. Security has been notified");
}

static string apiReset() {
    resetAll();
    seed();
    return msg(true, "Demo data reset to the 5 sample researchers");
}

static string apiResearcher(const Params &p) {
    string id = P(p, "id"), name = P(p, "name"), role = P(p, "role"), status = P(p, "status");
    string password = P(p, "password");
    if (id.empty() || name.empty()) return msg(false, "ID and name are required");
    if (password.size() < 4) return msg(false, "Choose a password of at least 4 characters");
    if (id.size() > 12) return msg(false, "ID can be at most 12 characters");
    for (size_t i = 0; i < id.size(); i++)
        if (!isalnum((unsigned char)id[i]) && id[i] != '-' && id[i] != '_') return msg(false, "ID can only use letters, numbers, - and _");
    if (status != "Restricted") status = "Authorized";
    if (role.empty()) role = "Researcher";
    if (!researchers.insert(makeResearcher(id, name, role, status, password))) return msg(false, "ID " + id + " already exists");
    zones.find(1)->allowed.insert(id);  // everyone starts with the general lab
    return msg(true, name + " registered with General Lab access");
}

// Save a real Windows Hello (WebAuthn) credential id as this researcher's fingerprint
static string apiEnroll(const Params &p) {
    string id = P(p, "id"), cred = P(p, "credential");
    int probes;
    Researcher *r = researchers.find(id, probes);
    if (!r) return msg(false, "Unknown researcher");
    if (cred.size() < 8 || cred.compare(0, 3, "WA:") != 0) return msg(false, "Not a valid fingerprint credential");
    r->fingerprint = cred;
    return msg(true, r->name + " enrolled with this laptop's fingerprint reader");
}

static string apiPermission(const Params &p) {
    string id = P(p, "id"), action = P(p, "action");
    int probes;
    Researcher *r = researchers.find(id, probes);
    Zone *z = zones.find(toInt(P(p, "zone"), 0));
    if (!r || !z) return msg(false, "Unknown researcher or zone");
    if (action == "grant") { z->allowed.insert(id); return msg(true, r->name + " can now enter " + z->name); }
    z->allowed.erase(id);
    return msg(true, r->name + " no longer has access to " + z->name);
}

static string apiLookup(const Params &p) {
    string id = P(p, "id");
    int probes;
    Researcher *r = researchers.find(id, probes);
    int b = researchers.hashOf(id);
    vector<string> chain = researchers.chainIds(b);
    string s = "{\"id\":" + q(id) + ",\"bucket\":" + itos(b) + ",\"probes\":" + itos(probes) +
               ",\"found\":" + string(r ? "true" : "false") + ",\"name\":" + q(r ? r->name : "") + ",\"chain\":[";
    for (size_t i = 0; i < chain.size(); i++) { if (i) s += ","; s += q(chain[i]); }
    return s + "]}";
}

static string apiLogs(const Params &p) {
    string by = P(p, "sort");
    vector<LogEntry> v = auditLog;
    if (by == "id") mergeSort(v, 0, (int)v.size(), byId);
    else if (by == "severity") mergeSort(v, 0, (int)v.size(), bySeverity);
    else mergeSort(v, 0, (int)v.size(), byTime);
    return "{\"sort\":" + q(by.empty() ? "time" : by) + ",\"logs\":" + logsJson(v) + "}";
}

// Sort by researcher ID (merge sort), then binary search for the first match
static string apiSearch(const Params &p) {
    string key = P(p, "id");
    vector<LogEntry> v = auditLog;
    mergeSort(v, 0, (int)v.size(), byId);
    int lo = 0, hi = (int)v.size(), steps = 0;
    string trace = "[";
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (steps) trace += ",";
        steps++;
        trace += "{\"lo\":" + itos(lo) + ",\"hi\":" + itos(hi - 1) + ",\"mid\":" + itos(mid) + "}";
        if (v[mid].id < key) lo = mid + 1; else hi = mid;
    }
    int count = 0;
    while (lo + count < (int)v.size() && v[lo + count].id == key) count++;
    return "{\"key\":" + q(key) + ",\"first\":" + itos(count ? lo : -1) + ",\"count\":" + itos(count) +
           ",\"steps\":" + itos(steps) + ",\"trace\":" + trace + "],\"logs\":" + logsJson(v) + "}";
}

static bool route(const string &path, const Params &p, string &out) {
    if (path == "/api/state") out = stateJson();
    else if (path == "/api/request") out = apiRequest(p);
    else if (path == "/api/emergency") out = apiEmergency(p);
    else if (path == "/api/process") out = apiProcess();
    else if (path == "/api/door") out = apiDoor(p);
    else if (path == "/api/alert") out = apiAlert(p);
    else if (path == "/api/reset") out = apiReset();
    else if (path == "/api/researcher") out = apiResearcher(p);
    else if (path == "/api/permission") out = apiPermission(p);
    else if (path == "/api/enroll") out = apiEnroll(p);
    else if (path == "/api/lookup") out = apiLookup(p);
    else if (path == "/api/logs") out = apiLogs(p);
    else if (path == "/api/search") out = apiSearch(p);
    else return false;
    if (path != "/api/state" && path != "/api/lookup" && path != "/api/logs" && path != "/api/search") saveAll();  // keep the data file current
    return true;
}

// ============================================================
//  TINY HTTP SERVER (plain sockets, one thread, select() loop)
// ============================================================
static string urlDecode(const string &s) {
    string o;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '+') o += ' ';
        else if (s[i] == '%' && i + 2 < s.size()) { o += (char)strtol(s.substr(i + 1, 2).c_str(), NULL, 16); i += 2; }
        else o += s[i];
    }
    return o;
}
static void parseParams(const string &s, Params &p) {
    size_t i = 0;
    while (i < s.size()) {
        size_t amp = s.find('&', i);
        string pair = s.substr(i, amp == string::npos ? string::npos : amp - i);
        size_t eq = pair.find('=');
        if (eq != string::npos) p[urlDecode(pair.substr(0, eq))] = urlDecode(pair.substr(eq + 1));
        if (amp == string::npos) break;
        i = amp + 1;
    }
}
static string mimeOf(const string &path) {
    size_t d = path.rfind('.');
    string e = d == string::npos ? "" : path.substr(d);
    if (e == ".html") return "text/html; charset=utf-8";
    if (e == ".css") return "text/css; charset=utf-8";
    if (e == ".js") return "application/javascript; charset=utf-8";
    if (e == ".svg") return "image/svg+xml";
    if (e == ".png") return "image/png";
    if (e == ".ico") return "image/x-icon";
    return "application/octet-stream";
}
static bool readFile(const string &path, string &out) {
    ifstream f(path.c_str(), ios::binary);
    if (!f) return false;
    ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}
static string httpResponse(int code, const string &ctype, const string &body) {
    const char *st = code == 200 ? "OK" : (code == 404 ? "Not Found" : "Bad Request");
    return "HTTP/1.1 " + itos(code) + " " + st + "\r\nContent-Type: " + ctype + "\r\nContent-Length: " + itos((long long)body.size()) +
           "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n" + body;
}
static bool requestComplete(const string &b, size_t &headEnd) {
    headEnd = b.find("\r\n\r\n");
    if (headEnd == string::npos) return false;
    string low = b.substr(0, headEnd);
    for (size_t i = 0; i < low.size(); i++) low[i] = (char)tolower((unsigned char)low[i]);
    size_t len = 0, k = low.find("content-length:");
    if (k != string::npos) len = (size_t)strtol(low.c_str() + k + 15, NULL, 10);
    return b.size() >= headEnd + 4 + len;
}
static string handleHttp(const string &buf, size_t headEnd) {
    string line = buf.substr(0, buf.find("\r\n"));
    size_t s1 = line.find(' '), s2 = line.find(' ', s1 + 1);
    if (s1 == string::npos || s2 == string::npos) return httpResponse(400, "text/plain", "Bad request");
    string target = line.substr(s1 + 1, s2 - s1 - 1), path = target, query;
    size_t qm = target.find('?');
    if (qm != string::npos) { path = target.substr(0, qm); query = target.substr(qm + 1); }
    Params p;
    parseParams(query, p);
    parseParams(buf.substr(headEnd + 4), p);  // form-encoded POST body

    string body;
    if (path.compare(0, 5, "/api/") == 0) {
        if (route(path, p, body)) return httpResponse(200, "application/json; charset=utf-8", body);
        return httpResponse(404, "application/json", msg(false, "Unknown API route"));
    }
    if (path == "/") path = "/index.html";
    if (path.find("..") != string::npos) return httpResponse(400, "text/plain", "Bad path");
    string data;
    if (!readFile("public" + path, data)) return httpResponse(404, "text/plain", "Not found: " + path);
    return httpResponse(200, mimeOf(path), data);
}
static void sendAll(sock_t s, const string &data) {
    size_t sent = 0;
    while (sent < data.size()) {
        int n = ::send(s, data.c_str() + sent, (int)(data.size() - sent), MSG_NOSIGNAL);
        if (n <= 0) break;
        sent += (size_t)n;
    }
}

struct Conn { sock_t s; string buf; };

int main() {
    int loaded = loadAll();
    if (loaded != 1) {
        if (loaded == -2) {
            remove("labdata.old");
            rename(DATA_FILE, "labdata.old");
            cerr << "Saved data came from an older version (the lab was renamed and passwords use a new salt).\n"
                    "It was kept as labdata.old and fresh sample data is being created.\n";
        } else if (loaded < 0) {
            remove("labdata.bad");
            rename(DATA_FILE, "labdata.bad");
            cerr << "Saved data was damaged. It was kept as labdata.bad and a fresh data file is being created.\n";
        }
        resetAll();
        seed();
        saveAll();
    }
    {
        ifstream t("public/index.html");
        if (!t) { cerr << "Cannot find public/index.html. Run this program from the project folder.\n"; return 1; }
    }
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { cerr << "Winsock could not start.\n"; return 1; }
#endif
    sock_t ls = ::socket(AF_INET, SOCK_STREAM, 0);
    if (ls == INVALID_SOCKET) { cerr << "Could not create a socket.\n"; return 1; }
#ifndef _WIN32
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
#endif
    sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // this computer only
    if (::bind(ls, (sockaddr *)&addr, sizeof addr) != 0 || ::listen(ls, 16) != 0) {
        cerr << "Could not start the server. Is port 8080 already in use?\n";
        return 1;
    }
    cout << "\n  Bio Laboratory - Access Verification System\n";
    cout << (loaded == 1 ? "  Loaded saved data from labdata.txt\n" : "  Created a new data file: labdata.txt\n");
    cout << "  Open http://localhost:8080 in your browser (Ctrl+C to stop)\n\n";

    vector<Conn> conns;
    for (;;) {
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(ls, &rs);
        sock_t mx = ls;
        for (size_t i = 0; i < conns.size(); i++) { FD_SET(conns[i].s, &rs); if (conns[i].s > mx) mx = conns[i].s; }
        timeval tv;
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (::select((int)mx + 1, &rs, NULL, NULL, &tv) <= 0) continue;

        if (FD_ISSET(ls, &rs)) {
            sock_t c = ::accept(ls, NULL, NULL);
            if (c != INVALID_SOCKET) { Conn k; k.s = c; conns.push_back(k); }
        }
        // Browsers open spare idle connections, so we never block on one client.
        for (size_t i = 0; i < conns.size();) {
            bool done = false;
            if (FD_ISSET(conns[i].s, &rs)) {
                char chunk[4096];
                int n = ::recv(conns[i].s, chunk, sizeof chunk, 0);
                if (n <= 0) done = true;
                else {
                    conns[i].buf.append(chunk, (size_t)n);
                    size_t headEnd;
                    if (requestComplete(conns[i].buf, headEnd)) {
                        sendAll(conns[i].s, handleHttp(conns[i].buf, headEnd));
                        done = true;
                    }
                }
            }
            if (done) { CLOSESOCK(conns[i].s); conns.erase(conns.begin() + i); }
            else i++;
        }
    }
    return 0;
}
