/**
 * IW8-DedicatedServer - Packet Inspector
 *
 * Simple TCP/UDP listener used for network research and protocol analysis.
 *
 * Purpose:
 * This tool is intended to help document and understand networking behavior
 * while developing backend services such as matchmaking, lobbies, and
 * dedicated server infrastructure.
 *
 */

const net = require("net");
const dgram = require("dgram");
const fs = require("fs");
const path = require("path");

const PORT = 3074; // Default port for Demonware
const DUMP_DIR = "./captures";

if (!fs.existsSync(DUMP_DIR)) {
    fs.mkdirSync(DUMP_DIR);
}

function timestamp() {
    return new Date().toISOString();
}

function hexDump(buffer) {
    let result = "";

    for (let i = 0; i < buffer.length; i += 16) {
        const chunk = buffer.slice(i, i + 16);

        const hex = Array.from(chunk)
            .map(b => b.toString(16).padStart(2, "0"))
            .join(" ");

        const ascii = Array.from(chunk)
            .map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
            .join("");

        result += `${i.toString(16).padStart(4, "0")}  ${hex.padEnd(48)}  ${ascii}\n`;
    }

    return result;
}

function savePacket(protocol, source, data) {
    const filename = path.join(
        DUMP_DIR,
        `${Date.now()}_${protocol}_${source.replace(/[:.]/g, "_")}.bin`
    );

    fs.writeFileSync(filename, data);
}

function analyzePacket(data) {
    const first4 = data.slice(0, 4).toString("hex");

    return {
        length: data.length,
        first4Bytes: first4,
        printableRatio:
            [...data].filter(x => x >= 32 && x <= 126).length /
            Math.max(data.length, 1)
    };
}

/*
 * TCP
 */

const tcpServer = net.createServer(socket => {

    const client =
        `${socket.remoteAddress}:${socket.remotePort}`;

    console.log(`\n[TCP CONNECT] ${client}`);

    socket.on("data", data => {

        const info = analyzePacket(data);

        console.log(`
                    =================================================
                    [TCP PACKET]
                    Time: ${timestamp()}
                    From: ${client}
                    Length: ${info.length}
                    Magic: ${info.first4Bytes}
                    Printable: ${(info.printableRatio * 100).toFixed(2)}%
                    =================================================
        `);

        console.log(hexDump(data));

        savePacket("tcp", client, data);
    });

    socket.on("close", () => {
        console.log(`[TCP DISCONNECT] ${client}`);
    });

    socket.on("error", err => {
        console.error(`[TCP ERROR] ${err.message}`);
    });
});

tcpServer.listen(PORT, () => {
    console.log(`[TCP] Listening on ${PORT}`);
});

/*
 * UDP
 */

const udpServer = dgram.createSocket("udp4");

udpServer.on("message", (msg, rinfo) => {

    const client =
        `${rinfo.address}:${rinfo.port}`;

    const info = analyzePacket(msg);

    console.log(`
                =================================================
                [UDP PACKET]
                Time: ${timestamp()}
                From: ${client}
                Length: ${info.length}
                Magic: ${info.first4Bytes}
                Printable: ${(info.printableRatio * 100).toFixed(2)}%
                =================================================
    `);

    console.log(hexDump(msg));

    savePacket("udp", client, msg);
});

udpServer.on("listening", () => {
    console.log(`[UDP] Listening on ${PORT}`);
});

udpServer.bind(PORT);
