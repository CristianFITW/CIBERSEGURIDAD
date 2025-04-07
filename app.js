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
    if (req.session.usuario) {
        return next();
    }
    res.redirect("/login");
}

app.get("/", (req, res) => {
    const nombreUsuario = req.session.usuario ? sanitizeInput(req.session.usuario) : null;
    res.render("index", {
        nombreUsuario: nombreUsuario
    });
});

app.get("/login", (req, res) => {
    if (req.session.usuario) {
        return res.redirect("/bienvenido");
    }
    res.render("login");
});

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
                        
                        req.session.usuario = usuario;
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

app.get("/bienvenido", verificarSesion, (req, res) => {
    console.log("Accediendo a /bienvenido con usuario:", req.session.usuario);
    const nombreUsuario = sanitizeInput(req.session.usuario);
    res.render('bienvenido', {
        nombreUsuario: nombreUsuario
    });
});

app.get("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Error al destruir sesión:", err);
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
            
            req.session.regenerate((err) => {
                if (err) {
                    console.error("Error al regenerar sesión:", err);
                    return res.render('registro-exitoso');
                }
                req.session.usuario = usuario;
                req.session.save((err) => {
                    if (err) {
                        console.error("Error al guardar sesión:", err);
                    }
                    res.render('registro-exitoso');
                });
            });
        });
    });
});

app.get('/obtener-usuario', verificarSesion, (req, res) => {
    res.render('obtener-usuario');
});

app.get('/agregar-usuario', verificarSesion, (req, res) => {
    res.render('agregar-usuario');
});
app.post('/agregarUsuario', verificarSesion, validateRequestBody, (req, res) => {
    const { nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8 } = req.body;
    const creadoPor = req.session.usuario;

    // Verificación adicional para ver los datos que se están enviando
    console.log('Datos recibidos:', {
        nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8,
        creadoPor
    });

    con.query(
        'INSERT INTO usuario (nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8, creado_por) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 
        [nombre, nombre2, nombre3, nombre4, nombre5, nombre6, nombre7, nombre8, creadoPor], 
        (err, result) => {
            if (err) {
                console.error("Error detallado en la base de datos:", {
                    error: err,
                    sqlMessage: err.sqlMessage,
                    sql: err.sql
                });
                return res.status(500).render('error', { 
                    mensaje: "Error al guardar en la base de datos: " + err.sqlMessage 
                });
            }
            
            console.log('Jugador agregado correctamente:', result);
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
    const usuarioActual = req.session.usuario;
    
    con.query('SELECT * FROM usuario WHERE creado_por = ?', [usuarioActual], (err, resultados) => {
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
    const usuarioActual = req.session.usuario;

    if (!/^\d+$/.test(userId)) {
        return res.status(400).render('error', { 
            mensaje: "ID de usuario no válido" 
        });
    }

    con.query('DELETE FROM usuario WHERE id = ? AND creado_por = ?', [userId, usuarioActual], (err, respuesta) => {
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
    const nuevoNombre = req.body.nombre;
    const usuarioActual = req.session.usuario;

    if (!/^\d+$/.test(userId)) {
        return res.status(400).render('error', { 
            mensaje: "ID de usuario no válido" 
        });
    }

    con.query('UPDATE usuario SET nombre = ? WHERE id = ? AND creado_por = ?', 
        [nuevoNombre, userId, usuarioActual], 
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
function verificarSesion(req, res, next) {
    console.log('Sesión actual:', req.session);
    if (req.session.usuario) {
        return next();
    }
    res.redirect("/login");
}
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
});