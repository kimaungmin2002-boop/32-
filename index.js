const { Client, GatewayIntentBits } = require("discord.js");
const express = require("express");
const cors = require("cors");
const path = require("path");

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages
    ]
});

const app = express();
app.use(cors());

// 현재 폴더를 정적 파일 경로로 지정
app.use(express.static(__dirname));

app.get("/api/stats", (req, res) => {
    if (!client.isReady()) {
        return res.json({ status: "offline", servers: 0, users: 0 });
    }

    const serverCount = client.guilds.cache.size;
    const userCount = client.guilds.cache.reduce((acc, guild) => {
        return acc + (typeof guild.memberCount === "number" ? guild.memberCount : 0);
    }, 0);

    res.json({
        status: "online",
        servers: serverCount,
        users: userCount
    });
});

// Render에서 할당하는 포트를 우선적으로 사용
const PORT = process.env.PORT || 10000; 

app.listen(PORT, () => {
    console.log(`웹사이트와 API가 포트 ${PORT} 에서 작동 중입니다.`);
});

client.on("ready", () => {
    console.log(`봇이 성공적으로 로그인했습니다! (${client.user.tag})`);
});

client.login(process.env.DISCORD_TOKEN);