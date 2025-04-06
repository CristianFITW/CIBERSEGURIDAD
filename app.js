const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require('bcryptjs');
const session = require("express-session");
const path = require("path");
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));

// Configuración de la conexión a MySQL en Railway
const con = mysql.createConnection({
    host: 'gondola.proxy.rlwy.net', // Usando el host público de Railway
    user: 'root',
    password: 'GlGGCOExGiDLvJTbqWhEPfOGZxQqYGUX', // Contraseña proporcionada
    database: 'railway',
    port: 31695 // Puerto proporcionado
});

// Manejo de errores de conexión
con.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
        process.exit(1); // Salir si no podemos conectar a la DB
    }
    console.log('Conectado a la base de datos MySQL en Railway');
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: "secreto",
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 60 * 24
    }
}));

// Función para sanitizar y validar entradas
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    
    // Eliminar etiquetas HTML/XML
    let sanitized = input.replace(/<[^>]*>?/gm, '');
    
    // Eliminar caracteres potencialmente peligrosos para SQL
    sanitized = sanitized.replace(/['"\\;]/g, '');
    
    // Eliminar scripts y eventos
    sanitized = sanitized.replace(/script\s*:/gi, '');
    sanitized = sanitized.replace(/on\w+=\s*["'][^"']*["']/gi, '');
    
    return sanitized.trim();
}

// Función para validar un campo contra patrones maliciosos
function validateField(fieldValue, fieldName) {
    if (!fieldValue) return { valid: false, message: `${fieldName} es requerido` };
    
    const value = String(fieldValue);
    
    // Patrones de validación
    const sqlInjectionPattern = /(\b(SELECT|INSERT|UPDATE|DELETE|OR|DROP|UNION|EXEC|ALTER|CREATE|TRUNCATE)\b)|(--)|(#)/i;
    const xssPattern = /<script|<\/script>|javascript:|on\w+\s*=/i;
    const htmlPattern = /<[^>]*>?/;
    
    if (sqlInjectionPattern.test(value)) {
        return { valid: false, message: `El ${fieldName} contiene patrones sospechosos de SQL` };
    }
    
    if (xssPattern.test(value)) {
        return { valid: false, message: `El ${fieldName} contiene patrones sospechosos de XSS` };
    }
    
    if (htmlPattern.test(value)) {
        return { valid: false, message: `El ${fieldName} contiene HTML no permitido` };
    }
    
    return { valid: true };
}

// Middleware para validar todos los campos del body
function validateRequestBody(req, res, next) {
    for (const [key, value] of Object.entries(req.body)) {
        const validation = validateField(value, key);
        if (!validation.valid) {
            return res.status(400).render('error', { mensaje: validation.message });
        }
        // Sanitizar el valor antes de continuar
        req.body[key] = sanitizeInput(value);
    }
    next();
}

function verificarSesion(req, res, next) {
    if (req.session.usuario) {
        return next();
    }
    res.redirect("/login");
}

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", validateRequestBody, (req, res) => {
    const { usuario, contrasena } = req.body;

    // Validación adicional para credenciales
    if (!usuario || !contrasena) {
        return res.status(400).render('error', { 
            mensaje: "Usuario y contraseña son requeridos" 
        });
    }

    // Usar parámetros preparados para evitar SQL injection
    con.query("SELECT * FROM usuarios WHERE username = ?", [usuario], (err, resultados) => {
        if (err) return res.status(500).send("Error en la base de datos");

        if (resultados.length > 0) {
            bcrypt.compare(contrasena, resultados[0].password, (err, coincide) => {
                if (err) return res.status(500).send("Error en la verificación");

                if (coincide) {
                    req.session.usuario = usuario;
                    return res.redirect("/bienvenido");
                } else {
                    return res.status(401).render('error', { 
                        mensaje: "Credenciales incorrectas" 
                    });
                }
            });
        } else {
            return res.status(404).render('error', { 
                mensaje: "Usuario no encontrado" 
            });
        }
    });
});

app.get("/bienvenido", verificarSesion, (req, res) => {
    // Escapar el nombre de usuario antes de mostrarlo en la vista
    const nombreUsuario = sanitizeInput(req.session.usuario);
    res.render('bienvenido', {
        nombreUsuario: nombreUsuario
    });
});

app.get("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).render('error', { 
                mensaje: "Error al cerrar sesión" 
            });
        }
        res.clearCookie("connect.sid");
        res.redirect("/login");
    });
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", validateRequestBody, (req, res) => {
    const { usuario, contrasena } = req.body;

    if (!usuario || !contrasena) {
        return res.status(400).render('error', { 
            mensaje: "Usuario y contraseña son requeridos" 
        });
    }

    // Validar longitud mínima de contraseña
    if (contrasena.length < 8) {
        return res.status(400).render('error', { 
            mensaje: "La contraseña debe tener al menos 8 caracteres" 
        });
    }

    bcrypt.hash(contrasena, 10, (err, hash) => {
        if (err) {
            console.error("Error al encriptar:", err);
            return res.status(500).render('error', {
                mensaje: "Error al encriptar la contraseña"
            });
        }

        con.query("INSERT INTO usuarios (username, password) VALUES (?, ?)", 
        [usuario, hash], 
        (err, resultado) => {
            if (err) {
                console.error("Error en BD:", err);
                return res.status(500).render('error', {
                    mensaje: err.code === 'ER_DUP_ENTRY' 
                        ? "El usuario ya existe" 
                        : "Error al registrar usuario"
                });
            }
            
            res.render('registro-exitoso');
        });
    });
});

app.get("/", (req, res) => {
    const nombreUsuario = req.session.usuario ? sanitizeInput(req.session.usuario) : null;
    res.render("index", {
        nombreUsuario: nombreUsuario
    });
});

app.get('/obtener-usuario', verificarSesion, (req, res) => {
    res.render('obtener-usuario');
});

app.get('/agregar-usuario', verificarSesion, (req, res) => {
    res.render('agregar-usuario');
});

app.post('/agregarUsuario', verificarSesion, validateRequestBody, (req, res) => {
    const { 
        nombre, 
        nombre2, 
        nombre3, 
        nombre4, 
        nombre5, 
        nombre6, 
        nombre7, 
        nombre8 
    } = req.body;

    con.query(
        'INSERT INTO usuario (nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
        [nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8], 
        (err) => {
            if (err) {
                console.error("Error en la base de datos:", err);
                return res.status(500).render('error', { mensaje: "Error al guardar en la base de datos" });
            }
            
            res.render('info-usuario', {
                nombre: sanitizeInput(nombre),
                nombre2: sanitizeInput(nombre2),
                nombre3: sanitizeInput(nombre3),
                nombre4: sanitizeInput(nombre4),
                nombre5: sanitizeInput(nombre5),
                nombre6: sanitizeInput(nombre6),
                nombre7: sanitizeInput(nombre7),
                nombre8: sanitizeInput(nombre8)
            });
        }
    );
});

app.get('/obtenerUsuario', verificarSesion, (req, res) => {
    con.query('SELECT * FROM usuario', (err, resultados) => {
        if (err) {
            console.error("Error al obtener usuarios", err);
            return res.status(500).render('error', { 
                mensaje: "Error al obtener usuarios" 
            });
        }
        
        // Sanitizar todos los resultados antes de mostrarlos
        const usuariosSanitizados = resultados.map(usuario => {
            return {
                id: usuario.id,
                nombre: sanitizeInput(usuario.nombre),
                nombre2: sanitizeInput(usuario.nombre2),
                nombre3: sanitizeInput(usuario.nombre3),
                nombre4: sanitizeInput(usuario.nombre4),
                nombre5: sanitizeInput(usuario.nombre5),
                nombre6: sanitizeInput(usuario.nombre6),
                nombre7: sanitizeInput(usuario.nombre7),
                nombre8: sanitizeInput(usuario.nombre8)
            };
        });
        
        res.render('lista-usuarios', { 
            usuarios: usuariosSanitizados 
        });
    });
});

app.post('/eliminarUsuario/:id', verificarSesion, (req, res) => {
    const userId = sanitizeInput(req.params.id);

    // Validar que el ID sea numérico
    if (!/^\d+$/.test(userId)) {
        return res.status(400).render('error', { 
            mensaje: "ID de usuario no válido" 
        });
    }

    con.query('DELETE FROM usuario WHERE id = ?', [userId], (err, respuesta) => {
        if (err) {
            console.error("Error al eliminar usuario", err);
            return res.status(500).render('error', { 
                mensaje: "Error al eliminar usuario" 
            });
        }

        if (respuesta.affectedRows > 0) {
            return res.redirect('/obtenerUsuario'); 
        } else {
            return res.status(404).render('error', { 
                mensaje: `No se encontró un usuario con ID ${userId}` 
            });
        }
    });
});

app.post('/editarUsuario/:id', verificarSesion, validateRequestBody, (req, res) => {
    const userId = sanitizeInput(req.params.id);
    const nuevoNombre = req.body.nombre;

    // Validar que el ID sea numérico
    if (!/^\d+$/.test(userId)) {
        return res.status(400).render('error', { 
            mensaje: "ID de usuario no válido" 
        });
    }

    con.query('UPDATE usuario SET nombre = ? WHERE id = ?', [nuevoNombre, userId], (err, respuesta) => {
        if (err) {
            console.error("Error al actualizar usuario", err);
            return res.status(500).render('error', { 
                mensaje: "Error al actualizar usuario" 
            });
        }

        if (respuesta.affectedRows > 0) {
            return res.redirect('/obtenerUsuario'); 
        } else {
            return res.status(404).render('error', { 
                mensaje: `No se encontró un usuario con ID ${userId}` 
            });
        }
    });
});

// Middleware para manejar errores
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('error', { 
        mensaje: "Ocurrió un error interno en el servidor" 
    });
});

app.listen(3000, () => {
    console.log('Servidor escuchando en el puerto 3000');
});