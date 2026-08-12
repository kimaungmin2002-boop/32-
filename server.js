const express = require('express');
const cors = require('cors');
const os = require('os');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/stats', (req, res) => {
    const cpus = os.cpus();
    const freeMemory = os.freemem();
    const totalMemory = os.totalmem();
    const memoryUsagePercent = (((totalMemory - freeMemory) / totalMemory) * 100).toFixed(1);

    res.json({
        servers: 83,                  
        users: 5730,                  
        commands: 1200000,            
        cpuCores: cpus.length,        
        memoryUsage: memoryUsagePercent 
    });
});

app.listen(PORT, () => {
    console.log("✨ 마법 공방 서버가 열렸습니다! 접속 주소: http://localhost:" + PORT);
});
