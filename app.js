// Cargar las variables de entorno desde el archivo .env
require('dotenv').config();

// Importar las librerías necesarias
const express = require('express'); // Framework para crear aplicaciones web en Node.js
const bodyParser = require('body-parser'); // Middleware para parsear datos en el cuerpo de la solicitud
const bcrypt = require('bcryptjs'); // Librería para encriptar contraseñas
const jwt = require('jsonwebtoken'); // Librería para generar y verificar tokens JWT

// Inicializar la aplicación Express
const app = express();
const PORT = process.env.PORT || 3000; // Usar el puerto de la variable de entorno, si no, usar el puerto 3000

// Middleware para analizar el cuerpo de las solicitudes (permite manejar datos en formato JSON)
app.use(bodyParser.json());

// Simulación de una base de datos (en memoria)
let users = []; // Array para almacenar los usuarios registrados
const revokedTokens = new Set(); // Conjunto para almacenar tokens que han sido revocados (desactivados)

// Ruta base para la API
app.get('/', (req, res) => {
    res.json({ message: 'Bienvenido a la API de autenticación!' }); 
});

// Ruta para registrar un nuevo usuario
app.post('/register', async (req, res) => {
    const { username, password } = req.body; // Obtener los datos del cuerpo de la solicitud

    // Verificar que se haya enviado tanto el nombre de usuario como la contraseña
    if (!username || !password) {
        return res.status(400).json({ error: 'Faltan datos obligatorios.' }); 
    }

    // Verificar si el usuario ya existe en la "base de datos"
    const userExists = users.find((user) => user.username === username);
    if (userExists) {
        return res.status(400).json({ error: 'El usuario ya existe.' }); 
    }

    // Encriptar la contraseña del usuario antes de guardarla
    const hashedPassword = await bcrypt.hash(password, 10); 

    // Guardar el nuevo usuario en la "base de datos" 
    users.push({ username, password: hashedPassword });

    
    res.status(201).json({ message: 'Usuario registrado con éxito.' });
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
    const { username, password } = req.body; // Obtener los datos del cuerpo de la solicitud

    // Verificar que se haya enviado tanto el nombre de usuario como la contraseña
    if (!username || !password) {
        return res.status(400).json({ error: 'Faltan datos obligatorios.' });
    }

    // Buscar el usuario en la "base de datos"
    const user = users.find((user) => user.username === username);
    if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado.' }); // Error si el usuario no existe
    }

    // Verificar si la contraseña proporcionada es correcta comparándola con la contraseña almacenada
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ error: 'Contraseña incorrecta.' }); 
    }

    // Generar un token JWT que representará al usuario durante su sesión
    const token = jwt.sign({ username }, process.env.JWT_SECRET, {
        expiresIn: '1h', // El token expirará en 1 hora
    });

    // Responder con el token generado
    res.json({ message: 'Inicio de sesión exitoso.', token });
});

// Middleware para autenticar un token (verificar si es válido)
const authenticateToken = (req, res, next) => {
    // Obtener el token del encabezado Authorization (formato: "Bearer <token>")
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Si no se proporciona un token, rechazar la solicitud
    if (!token) {
        return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado.' });
    }

    // Verificar si el token ha sido revocado
    if (revokedTokens.has(token)) {
        return res.status(403).json({ error: 'Token revocado. Por favor, inicie sesión nuevamente.' });
    }

    // Verificar que el token sea válido usando JWT
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido o expirado.' }); // Error si el token es inválido o expiró
        }

        req.user = user; // Guardar los datos del usuario decodificados en la solicitud
        next(); // Continuar con la siguiente ruta
    });
};

// Ruta protegida que requiere autenticación mediante token
app.get('/protected', authenticateToken, (req, res) => {
    // Si el token es válido, acceder a esta ruta
    res.json({
        message: '¡Accediste a un recurso protegido!',
        user: req.user, // Información del usuario que está en el token
    });
});

// Ruta para cerrar sesión (revocar el token)
app.post('/api/logout', (req, res) => {
    // Obtener el token del encabezado Authorization
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Si no se proporciona un token, devolver error
    if (!token) {
        return res.status(400).json({ error: 'Token no proporcionado.' });
    }

    // Revocar el token (agregarlo al conjunto de tokens revocados)
    revokedTokens.add(token);

    // Responder que el cierre de sesión fue exitoso
    res.status(200).json({ message: 'Cierre de sesión exitoso.' });
});

// Iniciar el servidor y escuchar en el puerto especificado
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
