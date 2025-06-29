const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const admin = require("firebase-admin");
const nodemailer = require('nodemailer');
const router = express.Router();
const db = admin.firestore();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const JWT_SECRET = process.env.JWT_SECRET || "Uteq";

console.debug('Using JWT secret: ' + JWT_SECRET);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

router.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    const Secret = speakeasy.generateSecret({ length: 30 });

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

router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ statusCode: 400, message: 'Correo electrónico requerido.' });
    }

    try {
        const userRef = db.collection('users').doc(email);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ statusCode: 404, message: 'Usuario no encontrado.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        await db.collection('resetTokens').doc(email).set({
            otp: otp,
            expires: otpExpires,
            used: false,
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Código para restablecer tu contraseña',
            html: `
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #f4f4f4;
                            margin: 0;
                            padding: 0;
                        }
                        .container {
                            max-width: 600px;
                            margin: 50px auto;
                            background-color: #ffffff;
                            border-radius: 10px;
                            overflow: hidden;
                            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        }
                        .header {
                            background-color: #007bff;
                            color: #ffffff;
                            text-align: center;
                            padding: 20px;
                        }
                        .header img {
                            max-width: 150px;
                        }
                        .content {
                            padding: 20px;
                            text-align: center;
                        }
                        .otp-box {
                            background-color: #e9ecef;
                            padding: 15px;
                            border-radius: 5px;
                            display: inline-block;
                            font-size: 24px;
                            font-weight: bold;
                            color: #dc3545;
                            margin: 20px 0;
                        }
                        .footer {
                            background-color: #f8f9fa;
                            text-align: center;
                            padding: 10px;
                            font-size: 12px;
                            color: #6c757d;
                        }
                        a {
                            color: #007bff;
                            text-decoration: none;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Restablecimiento de Contraseña</h1>
                        </div>
                        <div class="content">
                            <p>Hola,</p>
                            <p>Tu código de verificación para restablecer la contraseña de tu cuenta es:</p>
                            <div class="otp-box">${otp}</div>
                            <p>Este código expira en <strong>10 minutos</strong>. 
                            <p>Por favor, no compartas este código con nadie.</p>
                            <p>Si no solicitaste el restablecimiento de contraseña ignora este correo o contacta a nuestro soporte.</p>
                        </div>
                        <div class="footer">
                          <p>© 2025 Eduquest. Todos los derechos reservados.</p>
                          <p>
                              <span>Contacto: </span>
                              <a href="mailto:support@eduquest.com">support@eduquest.com</a> | 
                              <a href="tel:+525512345678">+52 55 1234 5678</a>
                          </p>
                      </div>
                    </div>
                </body>
                </html>
            `,
        };
        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'Código de restablecimiento enviado al correo.' });
    } catch (error) {
        console.error('Error en forgot-password:', error);
        res.status(500).json({ statusCode: 500, message: 'Error interno al procesar la solicitud.' });
    }
});

router.post('/verify-otp-reset', async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ statusCode: 400, message: 'Correo y código requeridos.' });
    }

    try {
        const resetTokenRef = db.collection('resetTokens').doc(email);
        const resetTokenDoc = await resetTokenRef.get();

        if (!resetTokenDoc.exists) {
            return res.status(404).json({ statusCode: 404, message: 'Código no encontrado o expirado.' });
        }

        const resetTokenData = resetTokenDoc.data();

        if (resetTokenData.used) {
            return res.status(400).json({ statusCode: 400, message: 'El código ya fue utilizado.' });
        }

        if (new Date() > new Date(resetTokenData.expires)) {
            return res.status(400).json({ statusCode: 400, message: 'El código ha expirado.' });
        }

        if (resetTokenData.otp !== otp) {
            return res.status(401).json({ statusCode: 401, message: 'Código incorrecto.' });
        }

        await resetTokenRef.update({ used: true });

        res.json({ success: true, message: 'Código válido. Ingresa la nueva contraseña.' });
    } catch (error) {
        console.error('Error en verify-otp-reset:', error);
        res.status(500).json({ statusCode: 500, message: 'Error interno al verificar el código.' });
    }
});

router.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ statusCode: 400, message: 'Correo y nueva contraseña requeridos.' });
    }

    try {
        const resetTokenRef = db.collection('resetTokens').doc(email);
        const resetTokenDoc = await resetTokenRef.get();

        if (!resetTokenDoc.exists || !resetTokenDoc.data().used) {
            return res.status(400).json({ statusCode: 400, message: 'Debes verificar el código primero.' });
        }

        const userRef = db.collection('users').doc(email);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ statusCode: 404, message: 'Usuario no encontrado.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await userRef.update({
            password: hashedPassword,
        });

        await resetTokenRef.delete();

        res.json({ success: true, message: 'Contraseña actualizada correctamente.' });
    } catch (error) {
        console.error('Error en reset-password:', error);
        res.status(500).json({ statusCode: 500, message: 'Error interno al restablecer la contraseña.' });
    }
});

router.get("/logs2", async (req, res) => {
    try {
        const logsSnapshot1 = await db.collection("logs").get();
        const logsSnapshot2 = await db.collection("logs").get();
  
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
