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

const con = mysql.createConnection({
    host: 'gondola.proxy.rlwy.net',
    user: 'root',
    password: 'GlGGCOExGiDLvJTbqWhEPfOGZxQqYGUX',
    database: 'railway',
    port: 31695
});

con.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
        process.exit(1);
    }
    console.log('Conectado a la base de datos MySQL en Railway');
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.set('trust proxy', 1);
app.use(session({
    secret: "secreto",
    resave: true,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 1000 * 60 * 60 * 24,
        sameSite: 'lax'
    },
    store: new (require('express-session').MemoryStore)()
}));

function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    let sanitized = input.replace(/<[^>]*>?/gm, '');
    sanitized = sanitized.replace(/['"\\;]/g, '');
    sanitized = sanitized.replace(/script\s*:/gi, '');
    sanitized = sanitized.replace(/on\w+=\s*["'][^"']*["']/gi, '');
    return sanitized.trim();
}

function validateField(fieldValue, fieldName) {
    if (!fieldValue) return { valid: false, message: `${fieldName} es requerido` };
    
    const value = String(fieldValue);
    const sqlInjectionPattern = /((\b|\s)(SELECT|INSERT|CALL|EXEC|ALTER|CREATE|TRUNCATE|UNION|LOAD_FILE|BENCHMARK|SLEEP|IF|SUBSTRING)\b)|([\'\"](\\u[\da-fA-F]{4}|\s*OR\s*[1-9]))|(\/\*!|\*\/|--|#)/i;
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

function validateRequestBody(req, res, next) {
    for (const [key, value] of Object.entries(req.body)) {
        const validation = validateField(value, key);
        if (!validation.valid) {
            return res.status(400).render('error', { mensaje: validation.message });
        }
        req.body[key] = sanitizeInput(value);
    }
    next();
}

function verificarSesion(req, res, next) {
    console.log('Sesión actual:', req.session);
    if (req.session.usuario && req.session.usuarioId) {
        return next();
    }
    res.redirect("/login");
}

// Rutas de autenticación (login, register, logout) permanecen iguales hasta el inicio de sesión

app.post("/login", validateRequestBody, (req, res) => {
    const { usuario, contrasena } = req.body;

    if (!usuario || !contrasena) {
        return res.status(400).render('error', { 
            mensaje: "Usuario y contraseña son requeridos" 
        });
    }

    con.query("SELECT * FROM usuarios WHERE username = ?", [usuario], (err, resultados) => {
        if (err) {
            console.error("Error en la consulta:", err);
            return res.status(500).render('error', { mensaje: "Error en la base de datos" });
        }

        if (resultados.length > 0) {
            bcrypt.compare(contrasena, resultados[0].password, (err, coincide) => {
                if (err) {
                    console.error("Error al comparar contraseñas:", err);
                    return res.status(500).render('error', { mensaje: "Error en la verificación" });
                }

                if (coincide) {
                    req.session.regenerate((err) => {
                        if (err) {
                            console.error("Error al regenerar sesión:", err);
                            return res.status(500).render('error', { mensaje: "Error al iniciar sesión" });
                        }
                        
                        req.session.usuario = resultados[0].username;
                        req.session.usuarioId = resultados[0].id; // Guardar el ID del usuario
                        req.session.save((err) => {
                            if (err) {
                                console.error("Error al guardar sesión:", err);
                                return res.status(500).render('error', { mensaje: "Error al iniciar sesión" });
                            }
                            console.log("Sesión iniciada correctamente para:", usuario);
                            return res.redirect("/bienvenido");
                        });
                    });
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

// Resto de rutas de autenticación permanecen iguales...

// Rutas para manejar los jugadores

app.get('/obtener-usuario', verificarSesion, (req, res) => {
    res.render('obtener-usuario');
});

app.get('/agregar-usuario', verificarSesion, (req, res) => {
    res.render('agregar-usuario');
});

app.post('/agregarUsuario', verificarSesion, validateRequestBody, (req, res) => {
    const { nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8 } = req.body;
    const usuarioId = req.session.usuarioId;

    con.query(
        'INSERT INTO usuario (nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8, usuario_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 
        [nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8, usuarioId], 
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
    const usuarioId = req.session.usuarioId;
    
    con.query('SELECT * FROM usuario WHERE usuario_id = ?', [usuarioId], (err, resultados) => {
        if (err) {
            console.error("Error al obtener usuarios", err);
            return res.status(500).render('error', { 
                mensaje: "Error al obtener usuarios" 
            });
        }
        
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
    const usuarioId = req.session.usuarioId;

    if (!/^\d+$/.test(userId)) {
        return res.status(400).render('error', { 
            mensaje: "ID de usuario no válido" 
        });
    }

    con.query('DELETE FROM usuario WHERE id = ? AND usuario_id = ?', [userId, usuarioId], (err, respuesta) => {
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
                mensaje: `No se encontró un usuario con ID ${userId} o no tienes permiso para eliminarlo` 
            });
        }
    });
});

app.post('/editarUsuario/:id', verificarSesion, validateRequestBody, (req, res) => {
    const userId = sanitizeInput(req.params.id);
    const { nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8 } = req.body;
    const usuarioId = req.session.usuarioId;

    if (!/^\d+$/.test(userId)) {
        return res.status(400).render('error', { 
            mensaje: "ID de usuario no válido" 
        });
    }

    con.query(
        'UPDATE usuario SET nombre = ?, nombre2 = ?, nombre3 = ?, nombre4 = ?, nombre5 = ?, nombre6 = ?, nombre7 = ?, nombre8 = ? WHERE id = ? AND usuario_id = ?', 
        [nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8, userId, usuarioId], 
        (err, respuesta) => {
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
                    mensaje: `No se encontró un usuario con ID ${userId} o no tienes permiso para editarlo` 
                });
            }
        }
    );
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('error', { 
        mensaje: "Ocurrió un error interno en el servidor" 
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
});