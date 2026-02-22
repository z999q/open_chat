// ==========================================================================
// 1. CORE STATE & INITIALIZATION
// ==========================================================================
const socket = io();
const enc = new TextEncoder();
const dec = new TextDecoder();

let roomPassword = '';
let username = '';
let db;
let localDBKey = null; 
let myECDHKeyPair = null;
let peerSessionKeys = {}; 
let peerRawPubKeys = {}; 
const seenMessageIds = new Set();

// 24 Hours in milliseconds for Disappearing Messages
const MESSAGE_EXPIRY_MS = 24 * 60 * 60 * 1000; 

// Auto-Login if tab was accidentally refreshed
window.addEventListener('DOMContentLoaded', () => {
    if (sessionStorage.getItem('activeKey')) {
        document.getElementById('secret-key').value = sessionStorage.getItem('activeKey');
        document.getElementById('username').value = sessionStorage.getItem('activeUser');
        initializeSecureSession();
    }
});

// ==========================================================================
// 2. CRYPTO & DATABASE SETUP
// ==========================================================================
async function generateECDH() {
    myECDHKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
    );
}

async function deriveDBKey(password) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveBits", "deriveKey"]
    );
    localDBKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: enc.encode("fixed-salt-chat-db"), iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
}

const request = indexedDB.open("E2EE_MilitaryDB", 1);
request.onupgradeneeded = (e) => {
    db = e.target.result;
    db.createObjectStore("messages", { keyPath: "id", autoIncrement: true })
      .createIndex("roomKey", "roomKey", { unique: false });
};
request.onsuccess = (e) => { db = e.target.result; };

// ==========================================================================
// 3. LOGIN & HANDSHAKE
// ==========================================================================
async function initializeSecureSession() {
    roomPassword = document.getElementById('secret-key').value;
    username = document.getElementById('username').value.trim() || 'Anonymous';
    
    if(!roomPassword) {
        alert("Please enter a Room Password.");
        return;
    }

    // Save to session storage to survive F5 refreshes
    sessionStorage.setItem('activeKey', roomPassword);
    sessionStorage.setItem('activeUser', username);
    
    // Switch UI Screens (Hide Setup, Show Chat)
    document.getElementById('setup-screen').classList.remove('active');
    document.getElementById('setup-screen').style.display = 'none';
    document.getElementById('chat-screen').classList.add('active');
    document.getElementById('chat-screen').style.display = 'flex';
    document.getElementById('chat-box').innerHTML = ''; // Clear chat box
    
    // Cryptography Initialization
    await deriveDBKey(roomPassword);
    loadChatHistory();
    await generateECDH();
    
    // Announce presence to the room
    const exportedPub = await crypto.subtle.exportKey("jwk", myECDHKeyPair.publicKey);
    socket.emit('announce_public_key', { pubKey: exportedPub });
    
    updateSafetyNumber(); 
}

// ==========================================================================
// 4. ECDH P2P EXCHANGE & SAFETY NUMBERS
// ==========================================================================
socket.on('receive_public_key', async (data) => {
    if (!myECDHKeyPair) return;
    
    peerRawPubKeys[data.sender_sid] = data.pubKey; 
    
    const peerPubKey = await crypto.subtle.importKey(
        "jwk", data.pubKey, {name: "ECDH", namedCurve: "P-256"}, true, []
    );
    
    const sharedSecret = await crypto.subtle.deriveKey(
        {name: "ECDH", public: peerPubKey}, myECDHKeyPair.privateKey,
        {name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"]
    );
    
    peerSessionKeys[data.sender_sid] = sharedSecret;
    updateSafetyNumber();

    if (!data.target_sid) {
        const exportedPub = await crypto.subtle.exportKey("jwk", myECDHKeyPair.publicKey);
        socket.emit('reply_public_key', { target_sid: data.sender_sid, pubKey: exportedPub });
    }
});

async function updateSafetyNumber() {
    if (!myECDHKeyPair) return;
    const keys = [ await crypto.subtle.exportKey("jwk", myECDHKeyPair.publicKey) ];
    for (let sid in peerRawPubKeys) { keys.push(peerRawPubKeys[sid]); }
    
    keys.sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    const hashBuffer = await crypto.subtle.digest("SHA-256", enc.encode(JSON.stringify(keys)));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    
    const num = ((hashArray[0] << 24) | (hashArray[1] << 16) | (hashArray[2] << 8) | hashArray[3]) >>> 0;
    const safetyCode = (num % 1000000).toString().padStart(6, '0');
    
    document.getElementById('safety-number-display').innerText = `Safety Code: ${safetyCode.slice(0,3)}-${safetyCode.slice(3)}`;
}

// ==========================================================================
// 5. MESSAGE TRANSMISSION (NETWORK)
// ==========================================================================
async function sendEncryptedNetworkPayload(type, content) {
    if (!localDBKey) return;

    const payloadData = {
        id: crypto.randomUUID(),
        timestamp: Date.now(), 
        sender: username,
        type: type,
        data: content
    };

    renderMessageDOM(payloadData.sender, type, content, new Date(payloadData.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
    await saveMessageToDB(payloadData);

    const msgKey = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertextBuffer = await crypto.subtle.encrypt({name: "AES-GCM", iv: iv}, msgKey, enc.encode(JSON.stringify(payloadData)));
    const rawMsgKey = await crypto.subtle.exportKey("raw", msgKey);
    
    let encryptedKeysForPeers = {};
    for (let [sid, sessionKey] of Object.entries(peerSessionKeys)) {
        const peerIv = crypto.getRandomValues(new Uint8Array(12));
        const wrappedKey = await crypto.subtle.encrypt({name: "AES-GCM", iv: peerIv}, sessionKey, rawMsgKey);
        encryptedKeysForPeers[sid] = { iv: Array.from(peerIv), wrappedKey: Array.from(new Uint8Array(wrappedKey)) };
    }

    socket.emit('send_encrypted_payload', {
        iv: Array.from(iv),
        ciphertext: Array.from(new Uint8Array(ciphertextBuffer)),
        keys: encryptedKeysForPeers
    });
}

socket.on('receive_encrypted_payload', async (data) => {
    if (!localDBKey) return; 
    try {
        const myKeyData = data.keys[socket.id];
        if(!myKeyData) return; 

        const sessionKey = peerSessionKeys[data.sender_sid];
        if(!sessionKey) throw new Error("No session key");

        const rawMsgKey = await crypto.subtle.decrypt(
            {name: "AES-GCM", iv: new Uint8Array(myKeyData.iv)}, sessionKey, new Uint8Array(myKeyData.wrappedKey)
        );
        const msgKey = await crypto.subtle.importKey("raw", rawMsgKey, {name: "AES-GCM", length: 256}, true, ["decrypt"]);
        
        const plaintextBuffer = await crypto.subtle.decrypt(
            {name: "AES-GCM", iv: new Uint8Array(data.iv)}, msgKey, new Uint8Array(data.ciphertext)
        );

        const payload = JSON.parse(dec.decode(plaintextBuffer));

        if (seenMessageIds.has(payload.id)) return; 
        seenMessageIds.add(payload.id);

        if (Date.now() - payload.timestamp > MESSAGE_EXPIRY_MS) return;

        renderMessageDOM(payload.sender, payload.type, payload.data, new Date(payload.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
        await saveMessageToDB(payload);
    } catch (error) {
        renderSysMsg('🔒 [Decryption Failed - Forward Secrecy enforced]');
    }
});

// ==========================================================================
// 6. DATABASE (AT REST) & EPHEMERAL PURGE
// ==========================================================================
async function saveMessageToDB(payload) {
    if (!db || !localDBKey) return;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const dbCiphertext = await crypto.subtle.encrypt(
        {name: "AES-GCM", iv: iv}, localDBKey, enc.encode(JSON.stringify(payload))
    );
    const transaction = db.transaction(["messages"], "readwrite");
    transaction.objectStore("messages").add({ 
        roomKey: roomPassword, 
        iv: Array.from(iv), 
        ciphertext: Array.from(new Uint8Array(dbCiphertext)) 
    });
}

function loadChatHistory() {
    if (!db || !localDBKey) return;
    const transaction = db.transaction(["messages"], "readwrite");
    const store = transaction.objectStore("messages");
    const getRequest = store.index("roomKey").getAll(roomPassword);

    getRequest.onsuccess = async (e) => {
        const messages = e.target.result;
        for (let msg of messages) {
            try {
                const plaintextBuffer = await crypto.subtle.decrypt(
                    {name: "AES-GCM", iv: new Uint8Array(msg.iv)}, localDBKey, new Uint8Array(msg.ciphertext)
                );
                const payload = JSON.parse(dec.decode(plaintextBuffer));
                
                // 24 Hour Ephemeral Purge
                if (Date.now() - payload.timestamp > MESSAGE_EXPIRY_MS) {
                    store.delete(msg.id); 
                    continue; 
                }

                seenMessageIds.add(payload.id); 
                renderMessageDOM(payload.sender, payload.type, payload.data, new Date(payload.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
            } catch (err) { console.error("DB Decryption Error"); }
        }
    };
}

// ==========================================================================
// 7. XSS-SAFE DOM MANIPULATION (WHATSAPP UI)
// ==========================================================================
function renderMessageDOM(sender, type, content, timeStr) {
    const chatBox = document.getElementById('chat-box');
    
    // Create the main bubble container
    const msgDiv = document.createElement('div');
    msgDiv.classList.add('message');
    
    // Check sender to apply correct WhatsApp bubble color and alignment
    if (sender === username) {
        msgDiv.classList.add('sent');
    } else {
        msgDiv.classList.add('received');
    }
    
    // Sender Name Header
    const header = document.createElement('strong');
    header.textContent = sender;
    msgDiv.appendChild(header);

    // Message Content
    const contentDiv = document.createElement('div');
    contentDiv.className = 'msg-content';
    
    if (type === 'text') {
        contentDiv.textContent = content; // Safely escapes HTML
    } else if (type === 'image') {
        const img = document.createElement('img');
        img.src = content;
        contentDiv.appendChild(img);
    }
    msgDiv.appendChild(contentDiv);

    // Timestamp
    const timeSpan = document.createElement('span');
    timeSpan.className = 'time';
    timeSpan.textContent = timeStr;
    msgDiv.appendChild(timeSpan);

    chatBox.appendChild(msgDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function renderSysMsg(text) {
    const chatBox = document.getElementById('chat-box');
    const sysDiv = document.createElement('div');
    sysDiv.className = 'sys-msg';
    sysDiv.textContent = text; 
    chatBox.appendChild(sysDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
}

// ==========================================================================
// 8. INPUT LISTENERS
// ==========================================================================
function sendUIAction() {
    const input = document.getElementById('msg-input');
    if (input.value.trim() !== '') {
        sendEncryptedNetworkPayload('text', input.value.trim());
        input.value = '';
    }
}

document.getElementById('msg-input').addEventListener('keypress', e => { 
    if (e.key === 'Enter') sendUIAction(); 
});

document.getElementById('img-input').addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = event => sendEncryptedNetworkPayload('image', event.target.result);
    reader.readAsDataURL(file);
});

// ==========================================================================
// 9. CAMERA FUNCTIONALITY
// ==========================================================================
let currentStream = null;

async function openCamera(facingMode) {
    if (!localDBKey) { alert("Connect to a room first!"); return; }
    const modal = document.getElementById('camera-modal');
    const video = document.getElementById('camera-stream');
    
    if (currentStream) currentStream.getTracks().forEach(track => track.stop());
    
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: facingMode } });
        currentStream = stream;
        video.srcObject = stream;
        modal.style.display = 'flex';
    } catch (err) { 
        alert("Camera access denied or unavailable."); 
    }
}

function closeCamera() {
    document.getElementById('camera-modal').style.display = 'none';
    if (currentStream) { 
        currentStream.getTracks().forEach(track => track.stop()); 
        currentStream = null; 
    }
}

function takeSnapshot() {
    const video = document.getElementById('camera-stream');
    const canvas = document.getElementById('camera-canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
    
    // Compress immediately to standard JPEG quality for fast transmission
    sendEncryptedNetworkPayload('image', canvas.toDataURL('image/jpeg', 0.8));
    closeCamera();
}

// ==========================================================================
// 10. SYSTEM EVENTS & PROTECTIONS
// ==========================================================================
window.addEventListener('beforeunload', e => { 
    if (localDBKey) { e.preventDefault(); e.returnValue = ''; } 
});

socket.on('system_message', data => { renderSysMsg(data.msg); });
