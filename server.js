const express = require('express');
const admin = require("firebase-admin");
const cors = require('cors');
const bodyParser = require('body-parser');
const winston = require('winston');

require('dotenv').config();
const PORT = 5001;

const serviceAccount = JSON.parse(process.env.serviceAccountKey);

if (!admin.apps.length) { 
    admin.initializeApp({ 
        credential: admin.credential.cert(serviceAccount), 
    }); 
} else { 
    admin.app();
}

const routes = require('./routes');

const server = express();

server.use(
    cors({
        origin: 'http://localhost:3001',
        credentials: true,
    })
);

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
      new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
      new winston.transports.File({ filename: 'logs/all.log', level: 'info' }),
      new winston.transports.File({ filename: 'logs/combined.log'}),
    ],
});


server.use(bodyParser.json());
const db = admin.firestore();


server.use((req, res, next) => {

    console.log(`📡[${req.method}] ${req.url} - Body:`, req.body);
    const startTime = Date.now();

    const originalSend = res.send;
    let statusCode;

    res.send = function(body) {
        statusCode = res.statusCode;
        originalSend.call(this, body);
    };

    res.on('finish', async () => {

        let logLevel;
        if (statusCode >= 500) {
            logLevel = 'error';
        } else if (statusCode >= 400) {
            logLevel = 'warn';
        } else if (statusCode >= 300) {
            logLevel = 'info';
        } else if (statusCode >= 200) {
            logLevel = 'info';
        } else {
            logLevel = 'debug';
        }

        const responseTime = Date.now() - startTime;
        const logData = {
            logLevel: logLevel,
            Timestamp: new Date(),
            method: req.method,
            url: req.url,
            path: req.path,
            query: req.query,
            params: req.params,
            username: req.body.username,
            email: req.body.email,
            password: req.body.password,
            status: statusCode || res.statusCode,
            responseTime: responseTime,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            protocol: req.protocol,
            hostname: req.hostname,
            system: {
                nodeVersion: process.version,
                enviroment: process.env.NODE_ENV || 'development',
                pid: process.pid,
            },
        };
        
    logger.log({
        level: logLevel,
        message: 'Request completed',
        ...logData
    });
    
    logger.info(logData);
    
    try {
        await db.collection('logs_server2').add(logData);
    } catch (error) {
        logger.error('Error al guardar el log en Firestore', error);
    }
    });
    next();
});

server.use('/api', routes);

// const verifyToken = (req, res, next) => {
//     const token = req.headers["authorization"];

//     if (!token) 
//         return res.status(403).json({ message: "Token no proporcionado" });
    
//     jwt.verify(token.split(" ")[1], SECRET_KEY, (err, decoded) => {
//         if (err) {
//             return res.status(401).json({ message: "Token inválido o expirado" });
//         }
//         req.user = decoded;
//         next();
//     });
// };

// server.get("/protected", verifyToken, (req, res) => {
//     res.json({ message: "Acceso permitido", user: req.user });
// });

server.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
