const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const admin = require("firebase-admin");
const router = express.Router();
const db = admin.firestore();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const JWT_SECRET = process.env.JWT_SECRET || "Uteq";

console.debug('Using JWT secret:' + JWT_SECRET);

router.post("/register", async (req, res) => {
    
  const { username, email, password } = req.body;

  const Secret = speakeasy.generateSecret({length: 30});

  if (!username || !email || !password) {
      return res.status(400).json({ statusCode: 400, message: "Complete todos los campos." });
  }

  try {
    
      const userSnapshot = await db.collection("users").where("username", "==", username).get();
      if (!userSnapshot.empty) {
          return res.status(400).json({ statusCode: 400, message: "Usuario ya registrado." });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = {
          email,
          username,
          password: hashedPassword,
          mfaSecret: Secret.base32,
      };

      const userRef = db.collection("users").doc(email);

      const doc = await userRef.get();
      
      if (doc.exists) {
        return res.status(400).json({ statusCode: 400, message: "Usuario ya registrado." });
      }

        await userRef.set(newUser);

      res.status(201).json({ statusCode: 201, message: "Usuario registrado correctamente." });
  } catch (error) {
      console.error(error);
      res.status(500).json({ statusCode: 500, message: "Error interno al registrar el usuario." });
  }
});

router.post("/login", async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
        return res.status(400).json({ statusCode: 400, message: "Complete todos los campos." });
    }

    try {    
        const userSnapshot = await db.collection("users").where("email", "==", email).get();
  
        if (userSnapshot.empty) {
            return res.status(401).json({ statusCode: 401, message: "Credenciales inválidas." });
        }
  
        const user = userSnapshot.docs[0].data();
        const passwordMatch = await bcrypt.compare(password, user.password);
  
        if (!passwordMatch) {
            return res.status(401).json({ statusCode: 401, message: "Credenciales inválidas." });
        }
  
        if (user.mfaSecret) {
            const otpAuthUrl = `otpauth://totp/MiApp:${email}?secret=${user.mfaSecret}&issuer=MiApp`;
            const qrCodeUrl = await qrcode.toDataURL(otpAuthUrl);
            return res.json({ requiresMFA: true, qrCodeUrl });
        }
  
        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1m" });
        return res.json({ success: true, token });
  
    } catch (error) {
        console.error(error);
        res.status(500).json({ statusCode: 500, message: "Error interno al iniciar sesión." });
    }
});

router.post('/verify-otp', async (req, res) => {
    const { email, token } = req.body;

    try {
        const userRef = db.collection("users").doc(email);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            
            return res.status(404).json({ message: "Usuario no encontrado." });
        }

        const userData = userDoc.data();

        if (!userData.mfaSecret) {
            
            return res.status(400).json({ message: "El usuario no tiene MFA habilitado." });
        }

        
        const isValid = speakeasy.totp.verify({
            secret: userData.mfaSecret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (!isValid) {
            
            return res.status(401).json({ message: "Código incorrecto o expirado." });
        }

        const jwtToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: "10m" });

        res.json({ success: true, token: jwtToken });

    } catch (error) {
        console.error("Error al inciar sesión:", error);
        res.status(500).json({ message: "Error interno al validar el código." });
    }
});


router.get("/logs2", async (req, res) => {
    try {
        
      const logsSnapshot1 = await db.collection("logs").get();
      // Logs de Server 2 (colección secundaria)
      const logsSnapshot2 = await db.collection("logs_server2").get();
  
      
      if (logsSnapshot1.empty && logsSnapshot2.empty) {
        return res.status(404).json({ message: "No hay logs en ningún servidor" });
      }
  
      
      const logs1 = logsSnapshot1.docs.map(doc => ({ ...doc.data(), server: "Servidor 1" }));
      const logs2 = logsSnapshot2.docs.map(doc => ({ ...doc.data(), server: "Servidor 2" }));
  
      
      const logs = [...logs1, ...logs2];
  
      res.json(logs);
    } catch (error) {
      console.error("Error al obtener logs:", error);
      res.status(500).json({ message: "Error al obtener logs", error: error.message });
    }
});
    
router.get("/logs/severity2", async (req, res) => {
    try {
        
      const logsSnapshot1 = await db.collection("logs").get();
      // Logs de Server 2 (colección secundaria)
      const logsSnapshot2 = await db.collection("logs_server2").get();
  
      
      const logs1 = logsSnapshot1.docs.map(doc => ({ ...doc.data(), server: "Servidor 1" }));
      const logs2 = logsSnapshot2.docs.map(doc => ({ ...doc.data(), server: "Servidor 2" }));
  
      
      const logs = [...logs1, ...logs2];
  
      const logLevelsByServer = logs.reduce((acc, log) => {
        const server = log.server || "Unknown";
        if (!acc[server]) acc[server] = {};
        acc[server][log.logLevel] = (acc[server][log.logLevel] || 0) + 1;
        return acc;
      }, {});
  
      res.json(logLevelsByServer);
    } catch (error) {
      console.error("Error al obtener logs por severidad:", error);
      res.status(500).json({ message: "Error al obtener logs por severidad" });
    }
});
  
router.get("/logs/methods2", async (req, res) => {
    try {
      const logsSnapshot1 = await db.collection("logs").get();
      const logsSnapshot2 = await db.collection("logs_server2").get();
  
      const logs1 = logsSnapshot1.docs.map(doc => ({ ...doc.data(), server: "Servidor 1" }));
      const logs2 = logsSnapshot2.docs.map(doc => ({ ...doc.data(), server: "Servidor 2" }));
  
      const logs = [...logs1, ...logs2];
  
      const methodsByServer = logs.reduce((acc, log) => {
        const server = log.server || "Unknown";
        if (!acc[server]) acc[server] = {};
        acc[server][log.method] = (acc[server][log.method] || 0) + 1;
        return acc;
      }, {});
  
      res.json(methodsByServer);
    } catch (error) {
      console.error("Error al obtener logs por método HTTP:", error);
      res.status(500).json({ message: "Error al obtener logs por método HTTP" });
    }
});
  
router.get("/logs/response-times2", async (req, res) => {
    try {
      const logsSnapshot1 = await db.collection("logs").get();
      const logsSnapshot2 = await db.collection("logs_server2").get();
  
      const logs1 = logsSnapshot1.docs.map(doc => ({ ...doc.data(), server: "Servidor 1" }));
      const logs2 = logsSnapshot2.docs.map(doc => ({ ...doc.data(), server: "Servidor 2" }));
  
      const logs = [...logs1, ...logs2];
  
      const responseTimesByServer = logs.reduce((acc, log) => {
        const server = log.server || "Unknown";
        if (!acc[server]) acc[server] = {};
        if (!acc[server][log.path]) acc[server][log.path] = { total: 0, count: 0 };
        acc[server][log.path].total += log.responseTime;
        acc[server][log.path].count += 1;
        return acc;
      }, {});
  
      const avgResponseTimesByServer = {};
      for (const server in responseTimesByServer) {
        avgResponseTimesByServer[server] = Object.keys(responseTimesByServer[server]).map(path => ({
          path,
          avgResponseTime: responseTimesByServer[server][path].total / responseTimesByServer[server][path].count
        }));
      }
  
      res.json(avgResponseTimesByServer);
    } catch (error) {
      console.error("Error al obtener tiempos de respuesta:", error);
      res.status(500).json({ message: "Error al obtener tiempos de respuesta" });
    }
});
  
router.get("/logs/users2", async (req, res) => {
    try {
      const logsSnapshot1 = await db.collection("logs").get();
      const logsSnapshot2 = await db.collection("logs_server2").get();
  
      const logs1 = logsSnapshot1.docs.map(doc => ({ ...doc.data(), server: "Servidor 1" }));
      const logs2 = logsSnapshot2.docs.map(doc => ({ ...doc.data(), server: "Servidor 2" }));
  
      const logs = [...logs1, ...logs2];
  
      
      const usersByServer = logs.reduce((acc, log) => {
        const server = log.server || "Unknown";
        acc[server] = (acc[server] || 0) + 1;
        return acc;
      }, {});
  
      res.json(usersByServer);
    } catch (error) {
      console.error("Error al obtener logs por usuario:", error);
      res.status(500).json({ message: "Error al obtener logs por usuario" });
    }
});

router.get('/getInfo', (req, res) => {
    res.json({
        nodeVersion: process.version,
        alumno: {
            grado: "Técnico Superior Universitario en Tecnologías de la Información Área Desarrollo de Software Multiplataforma",
            nombre: "Jose Angel Gonzalez Santafe",
            grupo: "IDGS011",
            profesor: "Mtr. Emmanuel Martinez Hernandez"
        },
        description: "Esta aplicación es un sistema de autenticación seguro que implementa registro de usuarios, inicio de sesión con autenticación multifactor (MFA) utilizando códigos OTP, y un sistema de logs para monitorear actividades en el servidor. Permite visualizar estadísticas de logs por severidad, métodos HTTP, tiempos de respuesta promedio y conteo por servidor en gráficas interactivas."
    });
});

module.exports = router;
