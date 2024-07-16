// Solo server
//pruebas con 0auth

require('dotenv').config();
const express = require('express');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const PassportLocal = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const mysql = require('mysql');
const bcrypt = require('bcrypt'); 

const app = express();

// Middleware para analizar datos de formularios
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('secreto'));

app.use(session({
    secret: 'secreto',
    resave: true,
    saveUninitialized: true
}));

// Configuración básica de passport
app.use(passport.initialize());
app.use(passport.session());

// Verifica que las variables de entorno están cargando correctamente
console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET);

// Conexión a la base de datos
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'genuiz'
});

connection.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
        return;
    }

    console.log('Conexión exitosa a la base de datos');
});

// Configuración de la estrategia PassportLocal
passport.use(new PassportLocal(async function (username, password, done) {
    console.log('Autenticando usuario con PassportLocal');
    const query = 'SELECT users.*, role.role_name FROM users LEFT JOIN role ON users.role_id = role.id WHERE username = ?';
    connection.query(query, [username], async (err, results) => {
        if (err) {
            return done(err);
        }
        if (results.length === 0) {
            console.log('Usuario no encontrado:', username);
            return done(null, false); // Usuario no encontrado
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            console.log('Contraseña incorrecta para usuario:', username);
            return done(null, false); // Contraseña incorrecta
        }
        if (user.role_id === null) {
            console.log('El usuario debe completar su registro:', username);
            return done(null, false, { message: 'Debe completar su registro.' });
        }
        console.log('Autenticación exitosa para usuario:', username);
        return done(null, user); // Autenticación exitosa
    });
}));

// Configuración google oauth 2.0 para inicio de sesión
passport.use('google-login', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/google/callback/login"
  },
  function(token, tokenSecret, profile, done) {
    console.log('Perfil recibido de Google para login:', profile);
    connection.query('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, results) => {
        if (err) {
            return done(err);
        }
        if (results.length === 0) {
            console.log('Usuario no encontrado para login:', profile.id);
            return done(null, false); // Usuario no encontrado
        } else {
            const user = results[0];
            if (user.role_id === null) {
                console.log('El usuario debe completar su registro:', profile.id);
                return done(null, user, { message: 'complete' }); // Usuario debe completar el registro
            }
            console.log('Usuario existente para login:', user);
            return done(null, user);
        }
    });
  }
));

// Configuracin google oauth 2.0 para registro
passport.use('google-register', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/google/callback/register"
  },
  function(token, tokenSecret, profile, done) {
    console.log('Perfil recibido de Google para registro:', profile);
    connection.query('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, results) => {
        if (err) {
            return done(err);
        }
        if (results.length === 0) {
            // Si el usuario no existe, crear uno nuevo
            const query = 'INSERT INTO users (google_id, username, name, role_id) VALUES (?, ?, ?, ?)';
            connection.query(query, [profile.id, profile.emails[0].value, profile.displayName, null], (err, results) => {
                if (err) {
                    return done(err);
                }
                const newUser = { id: results.insertId, username: profile.emails[0].value, name: profile.displayName, role_id: null };
                console.log('Nuevo usuario insertado:', newUser);
                return done(null, newUser);
            });
        } else {
            console.log('Usuario existente para registro:', results[0]);
            return done(null, false); // Usuario ya existente
        }
    });
  }
));

// Serialización del usuario
passport.serializeUser(function (user, done) {
    console.log('Serializando usuario con ID:', user.id);
    done(null, user.id);
});

// Deserialización del usuario
passport.deserializeUser(function (id, done) {
    console.log('Deserializando usuario con ID:', id);
    const query = 'SELECT users.*, role.role_name FROM users LEFT JOIN role ON users.role_id = role.id WHERE users.id = ?';
    connection.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error en la deserialización:', err);
            return done(err);
        }
        if (results.length === 0) {
            console.error('Usuario no encontrado');
            return done(new Error('Usuario no encontrado'), null);
        }
        console.log('Usuario deserializado:', results[0]);
        done(null, results[0]);
    });
});

// Rutas
app.get("/", (req, res) => {
    if (req.isAuthenticated()) {
        const userRole = req.user.role_name;
        if (userRole === 'student') {
            res.redirect("/vistaEstudiante.html");
        } else if (userRole === 'teacher') {
            res.redirect("/vistaProfesor.html");
        } else {
            res.send("Error: Rol de usuario desconocido.");
        }
    } else {
        res.redirect("/iniciosesion");
    }
});

app.get("/iniciosesion", (req, res) => {
    res.sendFile(path.join(__dirname, '..', '..', 'src', 'views', 'iniciosesion.html'));
});

// Ruta para el inicio de sesión
app.post("/iniciosesion", (req, res, next) => {
    passport.authenticate('local', function(err, user, info) {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.redirect('/iniciosesion?error=' + encodeURIComponent(info.message));
        }
        req.logIn(user, function(err) {
            if (err) {
                return next(err);
            }
            return res.redirect('/');
        });
    })(req, res, next);
});

// Ruta para la página de registro
app.get("/registrarme", (req, res) => {
    res.sendFile(path.join(__dirname, '..', '..', 'src', 'views', 'registrarme.html'));
});

// Ruta para el registro de usuario
app.post("/registrarme", (req, res, next) => {
    const { name, username, password, role } = req.body;

    console.log('Datos recibidos del formulario:', req.body);

    // Verifica si el usuario ya existe
    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error en la consulta', err);
            return res.redirect('/registrarme?error=database');
        }

        if (results.length > 0) {
            console.log('El usuario ya existe');
            return res.redirect('/registrarme?error=userexists');
        }

        // Obtener el role_id basado en el role_name
        connection.query('SELECT id FROM role WHERE role_name = ?', [role], (err, results) => {
            if (err || results.length === 0) {
                console.error('Error al obtener el role_id', err);
                return res.redirect('/registrarme?error=rolenotfound');
            }

            const role_id = results[0].id;

            console.log('Role ID:', role_id);

            // Agrega el usuario en la base de datos
            bcrypt.hash(password, 10, (err, hashedPassword) => {
                if (err) {
                    console.error('Error al hashear la contraseña', err);
                    return res.redirect('/registrarme?error=hash');
                }

                const query = 'INSERT INTO users (name, username, password, role_id) VALUES (?, ?, ?, ?)';
                connection.query(query, [name, username, hashedPassword, role_id], (err, results) => {
                    if (err) {
                        console.error('Error al registrar usuario', err);
                        return res.redirect('/registrarme?error=insert');
                    }

                    console.log('Usuario registrado:', { id: results.insertId, username, role_name: role });

                    // Autenticar al usuario registrado
                    req.login({ id: results.insertId, username, role_name: role }, (err) => {
                        if (err) {
                            return next(err);
                        }
                        return res.redirect('/');
                    });
                });
            });
        });
    });
});

// Ruta para autenticación con Google para login
app.get('/auth/google/login', passport.authenticate('google-login', { scope: ['profile', 'email'] }));

// Ruta de callback para Google login
app.get('/auth/google/callback/login', 
    passport.authenticate('google-login', { failureRedirect: '/iniciosesion?error=complete' }),
    (req, res) => {
        if (req.user.role_id === null) {
            return res.redirect('/completar-registro');
        }
        res.redirect('/');
    }
);

// Ruta para autenticación con Google para registro
app.get('/auth/google/register', passport.authenticate('google-register', { scope: ['profile', 'email'] }));

// Ruta de callback para Google registro
app.get('/auth/google/callback/register', 
    passport.authenticate('google-register', { failureRedirect: '/registrarme?error=userexists' }),
    (req, res) => {
        res.redirect('/completar-registro');
    }
);

// Ruta para completar el registro si el usuario no la ha completado (con google)
app.get('/completar-registro', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/iniciosesion');
    }
    res.sendFile(path.join(__dirname, '..', '..', 'src', 'views', 'completar-registro.html'));
});

app.post('/completar-registro', (req, res) => {
    const { role } = req.body;
    const userId = req.user.id;

    connection.query('SELECT id FROM role WHERE role_name = ?', [role], (err, results) => {
        if (err || results.length === 0) {
            console.error('Error al obtener el role_id', err);
            return res.redirect('/completar-registro');
        }

        const role_id = results[0].id;

        connection.query('UPDATE users SET role_id = ? WHERE id = ?', [role_id, userId], (err, results) => {
            if (err) {
                console.error('Error al actualizar usuario', err);
                return res.redirect('/completar-registro');
            }

            res.redirect('/');
        });
    });
});

// Ruta para servir archivos estáticos
app.use(express.static(path.join(__dirname, '..', '..', 'src', 'views')));

// Servir archivos HTML de las vistas
app.get('/vistaEstudiante.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', '..', 'src', 'views', 'vistaEstudiante.html'));
});

app.get('/vistaProfesor.html', (req, res) => {
    res.sendFile(path.join(__dirname, '..', '..', 'src', 'views', 'vistaProfesor.html'));
});

// Ruta de logout
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            return res.redirect('/?error=logout');
        }
        res.redirect('/iniciosesion');
    });
});

// Iniciar servidor
app.listen(8080, () => console.log("Server started"));
