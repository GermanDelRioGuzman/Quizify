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
const bodyParser = require('body-parser');
const flash = require('connect-flash');
const OpenAI = require('openai');

const app = express();
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('secreto'));
app.use(flash());

// Configuración de la sesión
app.use(session({
    secret: 'secreto',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

// Middleware para invalidar la caché
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.setHeader('Expires', '-1');
    res.setHeader('Pragma', 'no-cache');
    next();
});

// console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
// console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET);

//Conexión a la base de datos
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'admin',
    password: '080903',
    database: 'genuiz'
});

connection.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
        return;
    }
    console.log('Conexión exitosa a la base de datos');
});

// Configuración estrategia local de Passport
passport.use(new PassportLocal(async function (username, password, done) {
    const query = 'SELECT users.*, role.role_name FROM users LEFT JOIN role ON users.role_id = role.id WHERE username = ?';
    connection.query(query, [username], async (err, results) => {
        if (err) {
            return done(err);
        }
        if (results.length === 0) {
            return done(null, false, { message: 'Usuario no encontrado' });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return done(null, false, { message: 'Contraseña incorrecta' });
        }
        if (user.role_id === null) {
            return done(null, false, { message: 'Debe completar su registro.' });
        }
        return done(null, user);
    });
}));

// Configuración  Google  login
passport.use('google-login', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/google/callback/login"
},
function(token, tokenSecret, profile, done) {
    connection.query('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, results) => {
        if (err) {
            return done(err);
        }
        if (results.length === 0) {
            return done(null, false, { message: 'Usuario no encontrado' });
        } else {
            const user = results[0];
            if (user.role_id === null) {
                return done(null, user, { message: 'complete' });
            }
            return done(null, user);
        }
    });
}));

// Configuración  Google registro
passport.use('google-register', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/google/callback/register"
},
function(token, tokenSecret, profile, done) {
    connection.query('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, results) => {
        if (err) {
            return done(err);
        }
        if (results.length === 0) {
            const query = 'INSERT INTO users (google_id, username, name, role_id) VALUES (?, ?, ?, ?)';
            connection.query(query, [profile.id, profile.emails[0].value, profile.displayName, null], (err, results) => {
                if (err) {
                    return done(err);
                }
                const newUser = { id: results.insertId, username: profile.emails[0].value, name: profile.displayName, role_id: null };
                return done(null, newUser);
            });
        } else {
            return done(null, false, { message: 'Usuario ya existente' });
        }
    });
}));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    const query = 'SELECT users.*, role.role_name FROM users LEFT JOIN role ON users.role_id = role.id WHERE users.id = ?';
    connection.query(query, [id], (err, results) => {
        if (err) {
            return done(err);
        }
        if (results.length === 0) {
            return done(new Error('Usuario no encontrado'), null);
        }
        done(null, results[0]);
    });
});

// Para verificar autenticacion
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/iniciosesion');
}

function ensureRole(role) {
    return function(req, res, next) {
        if (req.isAuthenticated() && req.user.role_name === role) {
            return next();
        }
        res.sendStatus(403);
    }
}

// Ruta principal
app.get("/", ensureAuthenticated, (req, res) => {
    const userRole = req.user.role_name;
    if (userRole === 'student') {
        res.redirect("/vistaEstudiante.html");
    } else if (userRole === 'teacher') {
        res.redirect("/vistaProfesor.html");
    } else {
        res.send("Error: Rol de usuario desconocido.");
    }
});

// Ruta para iniciar sesión
app.get("/iniciosesion", (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'iniciosesion.html'));
});

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

// Ruta para registrarse
app.get("/registrarme", (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'registrarme.html'));
});

app.post("/registrarme", (req, res, next) => {
    const { name, username, password, role } = req.body;

    // Verificar si los datos están llegando correctamente
    console.log('Datos recibidos para registro:', req.body);

    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error en la consulta de usuarios:', err);
            return res.redirect('/registrarme?error=database');
        }

        if (results.length > 0) {
            console.log('Usuario ya existe:', results);
            return res.redirect('/registrarme?error=userexists');
        }

        connection.query('SELECT id FROM role WHERE role_name = ?', [role], (err, results) => {
            if (err) {
                console.error('Error en la consulta SELECT role:', err);
                return res.redirect('/registrarme?error=database');
            }

            if (results.length === 0) {
                console.log('Rol no encontrado:', role);
                return res.redirect('/registrarme?error=rolenotfound');
            }

            const role_id = results[0].id;
            console.log('Rol encontrado, role_id:', role_id);

            bcrypt.hash(password, 10, (err, hashedPassword) => {
                if (err) {
                    console.error('Error al hash el password:', err);
                    return res.redirect('/registrarme?error=hash');
                }

                const query = 'INSERT INTO users (name, username, password, role_id) VALUES (?, ?, ?, ?)';
                connection.query(query, [name, username, hashedPassword, role_id], (err, results) => {
                    if (err) {
                        console.error('Error al insertar el usuario:', err);
                        return res.redirect('/registrarme?error=insert');
                    }

                    console.log('Usuario registrado con éxito:', results);
                    req.login({ id: results.insertId, username, role_name: role }, (err) => {
                        if (err) {
                            console.error('Error en el login:', err);
                            return next(err);
                        }
                        return res.redirect('/');
                    });
                });
            });
        });
    });
});


// Autenticación con Google para login
app.get('/auth/google/login', passport.authenticate('google-login', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback/login', 
    passport.authenticate('google-login', { failureRedirect: '/iniciosesion?error=complete' }),
    (req, res) => {
        if (req.user.role_id === null) {
            return res.redirect('/completar-registro');
        }
        res.redirect('/');
    }
);

// Autenticación con Google para registro
app.get('/auth/google/register', passport.authenticate('google-register', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback/register', 
    passport.authenticate('google-register', { failureRedirect: '/registrarme?error=userexists' }),
    (req, res) => {
        res.redirect('/completar-registro');
    }
);

// Ruta para completar el registro
app.get('/completar-registro', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'completar-registro.html'));
});

app.post('/completar-registro', ensureAuthenticated, (req, res) => {
    const { role } = req.body;
    const userId = req.user.id;

    connection.query('SELECT id FROM role WHERE role_name = ?', [role], (err, results) => {
        if (err || results.length === 0) {
            return res.redirect('/completar-registro');
        }

        const role_id = results[0].id;

        connection.query('UPDATE users SET role_id = ? WHERE id = ?', [role_id, userId], (err, results) => {
            if (err) {
                console.error('Error al actualizar el rol del usuario:', err);
                return res.redirect('/completar-registro?error=update');
            }

            req.user.role_id = role_id;  // Actualiza el rol en el objeto de usuario en la sesión
            connection.query('SELECT role_name FROM role WHERE id = ?', [role_id], (err, results) => {
                if (err) {
                    console.error('Error al obtener el nombre del rol:', err);
                    return res.redirect('/completar-registro?error=rolename');
                }

                req.user.role_name = results[0].role_name;  // Actualiza el nombre del rol en el objeto de usuario en la sesión
                res.redirect('/');
            });
        });
    });
});

// Rutas para vistas específicas según el rol
app.get('/vistaEstudiante.html', ensureAuthenticated, ensureRole('student'), (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'vistaEstudiante.html'));
});

app.get('/vistaProfesor.html', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'vistaProfesor.html'));
});

app.get('/generador.html', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'generador.html'));
});

//nueva
app.get('/generador.html', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'editarExamen.html')); //ya funciona omg
});


// Ruta para cerrar sesión
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.redirect('/?error=logout');
        }
        req.session.destroy((err) => {
            if (err) {
                return res.redirect('/?error=logout');
            }
            res.clearCookie('connect.sid');
            res.redirect('/iniciosesion');
        });
    });
});

// Servir archivos estáticos  carpeta 'src/views'
app.use(express.static(path.join(__dirname, 'src', 'views')));

// Rutas para manejar exámenes
app.post('/recibir-datos', ensureAuthenticated, ensureRole('teacher'), async (req, res) => {
    if (!req.body || !req.body.miDato) {
        console.error('Petición incorrecta o falta el dato');
        return res.status(400).json({ error: "Bad Request or missing request" });
    }
    console.log('Dato recibido:', req.body.miDato);

    let miDato = req.body.miDato;
    let messages = [{ role: "user", content: miDato }];

    try {
        const openai = new OpenAI({
            apiKey: process.env.OPENAI_API_KEY
        });

        const completion = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: messages
        });

        let botResponse = completion.choices[0].message.content;
        console.log("Respuesta del bot (sin procesar):", botResponse);

        // Validar la estructura del JSON
        let parsedResponse;
        try {
            parsedResponse = JSON.parse(botResponse);
        } catch (error) {
            console.error("Error al parsear la respuesta JSON:", error);
            return res.status(500).json({ error: "Invalid JSON format from OpenAI" });
        }

        if (!parsedResponse || !parsedResponse.botResponse || !parsedResponse.botResponse.content) {
            console.error("Estructura de contenido inválida:", parsedResponse);
            return res.status(400).json({ error: "Invalid content structure" });
        }

        const processedResponse = {
            botResponse: {
                content: parsedResponse.botResponse.content
            }
        };

        console.log("Respuesta del bot (procesada):", processedResponse);

        res.json(processedResponse);
    } catch (error) {
        console.error("Error from OpenAI API", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.post('/save-exam', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    const { title, topic, description_, level, content } = req.body;
    const teacher_id = req.user.id;

    console.log("Usuario autenticado:", req.user);
    console.log("ID del profesor:", teacher_id);
    console.log("Datos recibidos para guardar:", req.body);

    // para verificar si la estructura es correcta
    if (!content || !content.preguntas || !Array.isArray(content.preguntas) || content.preguntas.length === 0) {
        console.error("Estructura de contenido inválida:", content);
        return res.status(400).json({ error: "Invalid content structure" });
    }

    const examData = content; // en formato JSON
    const examCode = Math.random().toString(36).substring(2, 10).toUpperCase(); // código único para el examen

    const examQuery = 'INSERT INTO exams_json (teacher_id, title, topic, description_, level, exam_code, exam_data) VALUES (?, ?, ?, ?, ?, ?, ?)';
    connection.query(examQuery, [teacher_id, title, topic, description_, level, examCode, JSON.stringify(examData)], (err, examResults) => {
        if (err) {
            console.error('Error al guardar el examen:', err);
            return res.status(500).json({ error: 'Error al guardar el examen' });
        }

        res.json({ message: 'Examen guardado correctamente', id: examResults.insertId, accessCode: examCode });
    });
});

app.get('/get-exams-json', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    connection.query('SELECT id, title, topic, level, date, exam_code, exam_data FROM exams_json WHERE teacher_id = ?', [req.user.id], (err, results) => {
        if (err) {
            console.error('Error al obtener los exámenes:', err);
            return res.status(500).send('Error al obtener los exámenes');
        }
        res.json(results);
    });
});

app.get('/get-exam-json', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    const examId = req.query.id;
    connection.query('SELECT * FROM exams_json WHERE id = ?', [examId], (err, results) => {
        if (err) {
            console.error('Error al obtener el examen:', err);
            return res.status(500).send('Error al obtener el examen');
        }
        if (results.length === 0) {
            return res.status(404).send({ message: 'Examen no encontrado' });
        }
        res.json(results[0]);
    });
});

// primero elimina resultados y cualquier registro dependiente al examed
app.delete('/delete-exam', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    const examId = req.query.id;

    const deleteResultsQuery = 'DELETE FROM exam_results WHERE exam_id = ?';
    connection.query(deleteResultsQuery, [examId], function (err) {
        if (err) {
            console.error('Error al eliminar los resultados del examen:', err);
            return res.status(500).send('Error al eliminar los resultados del examen');
        }

        // después elimina el examen 
        const deleteExamQuery = 'DELETE FROM exams_json WHERE id = ?';
        connection.query(deleteExamQuery, [examId], function (err) {
            if (err) {
                console.error('Error al eliminar el examen:', err);
                return res.status(500).send('Error al eliminar el examen');
            }
            res.status(200).send({ message: `Examen ${examId} eliminado correctamente` });
        });
    });
});

// Ruta para obtener un examen a través del código
app.get('/get-exam-by-code', ensureAuthenticated, ensureRole('student'), (req, res) => {
    const examCode = req.query.code;
    connection.query('SELECT * FROM exams_json WHERE exam_code = ?', [examCode], (err, results) => {
        if (err) {
            console.error('Error al obtener el examen:', err);
            return res.status(500).json({ error: 'Error al obtener el examen' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Examen no encontrado' });
        }
        res.json(results[0]);
    });
});

// Ruta para guardar el resultado del examen
app.post('/save-exam-result', ensureAuthenticated, ensureRole('student'), (req, res) => {
    const { examId, finalScore } = req.body;
    const userId = req.user.id;

    const query = 'INSERT INTO exam_results (user_id, exam_id, score) VALUES (?, ?, ?)';
    connection.query(query, [userId, examId, finalScore], (err, results) => {
        if (err) {
            console.error('Error al guardar el resultado del examen:', err);
            return res.status(500).json({ error: 'Error al guardar el resultado del examen' });
        }
        res.json({ message: 'Resultado guardado correctamente' });
    });
});

// Actualiza la ruta de vistaProfesor.html para mostrar los resultados
app.get('/get-exam-results', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    const examId = req.query.examId;
    const query = `
        SELECT er.*, u.username, u.name, er.timestamp 
        FROM exam_results er 
        JOIN users u ON er.user_id = u.id 
        WHERE er.exam_id = ?
    `;
    connection.query(query, [examId], (err, results) => {
        if (err) {
            console.error('Error al obtener los resultados:', err);
            return res.status(500).json({ error: 'Error al obtener los resultados' });
        }
        res.json(results);
    });
});

// Prueba para ver los datos del profe
app.get('/get-profesor-info', ensureAuthenticated, (req, res) => {
    const userId = req.user.id;
    const query = 'SELECT name, username FROM users WHERE id = ?';
    
    connection.query(query, [userId], (err, results) => {
      if (err) {
        console.error('Error al obtener la información del profesor:', err);
        return res.status(500).json({ error: 'Error al obtener la información del profesor' });
      }
      if (results.length > 0) {
        res.json(results[0]);
      } else {
        res.status(404).json({ error: 'Profesor no encontrado' });
      }
    });
  });
  
// Prueba para ver los datos del estudiante
app.get('/get-student-info', ensureAuthenticated, (req, res) => {
    const userId = req.user.id;
    const query = 'SELECT name, username FROM users WHERE id = ?';

    connection.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error al obtener la información del estudiante:', err);
            return res.status(500).json({ error: 'Error al obtener la información del estudiante' });
        }
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ error: 'Estudiante no encontrado' });
        }
    });
});

// Obtener resultados del estudiante
app.get('/get-student-results', ensureAuthenticated, ensureRole('student'), (req, res) => {
    const userId = req.user.id;
    const query = `
        SELECT 
            er.exam_id, 
            er.score, 
            er.timestamp, 
            e.title, 
            e.topic, 
            e.exam_code,
            u.name AS professor_name
        FROM exam_results er
        JOIN exams_json e ON er.exam_id = e.id
        JOIN users u ON e.teacher_id = u.id
        WHERE er.user_id = ?
    `;

    connection.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error al obtener los resultados del estudiante:', err);
            return res.status(500).json({ error: 'Error al obtener los resultados del estudiante' });
        }
        res.json(results);
    });
});

// Verificar si un examen ya ha sido respondido por el estudiante
app.get('/check-exam-result', ensureAuthenticated, ensureRole('student'), (req, res) => {
    const examId = req.query.examId;
    const userId = req.user.id;

    const query = `
        SELECT er.*, e.title, e.topic, e.exam_code
        FROM exam_results er
        JOIN exams_json e ON er.exam_id = e.id
        WHERE er.exam_id = ? AND er.user_id = ?
    `;

    connection.query(query, [examId, userId], (err, results) => {
        if (err) {
            console.error('Error al verificar el resultado del examen:', err);
            return res.status(500).json({ error: 'Error al verificar el resultado del examen' });
        }
        if (results.length > 0) {
            res.json({ alreadyTaken: true, examResult: results[0] });
        } else {
            res.json({ alreadyTaken: false });
        }
    });
});

// Obtener un examen a través del código
app.get('/get-exam-by-code', ensureAuthenticated, ensureRole('student'), (req, res) => {
    const examCode = req.query.code;

    const query = 'SELECT * FROM exams_json WHERE exam_code = ?';
    connection.query(query, [examCode], (err, results) => {
        if (err) {
            console.error('Error al obtener el examen:', err);
            return res.status(500).json({ error: 'Error al obtener el examen' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Examen no encontrado' });
        }
        res.json(results[0]);
    });
});

// Guardar el resultado del examen
app.post('/save-exam-result', ensureAuthenticated, ensureRole('student'), (req, res) => {
    const { examId, finalScore } = req.body;
    const userId = req.user.id;

    const query = 'INSERT INTO exam_results (user_id, exam_id, score) VALUES (?, ?, ?)';
    connection.query(query, [userId, examId, finalScore], (err, results) => {
        if (err) {
            console.error('Error al guardar el resultado del examen:', err);
            return res.status(500).json({ error: 'Error al guardar el resultado del examen' });
        }
        res.json({ message: 'Resultado guardado correctamente' });
    });
});

// Obtener un examen por ID
app.get('/get-exam-by-id', ensureAuthenticated, ensureRole('student'), (req, res) => {
    const examId = req.query.id;

    const query = 'SELECT * FROM exams_json WHERE id = ?';
    connection.query(query, [examId], (err, results) => {
        if (err) {
            console.error('Error al obtener el examen:', err);
            return res.status(500).json({ error: 'Error al obtener el examen' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Examen no encontrado' });
        }
        res.json(results[0]);
    });
});

// Eliminar un usuario MANUALMENTE (o sea en la base de datos)
app.delete('/delete-user', ensureAuthenticated, (req, res) => {
    const userId = req.query.id;

    connection.query('DELETE FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error al eliminar el usuario:', err);
            return res.status(500).send('Error al eliminar el usuario.');
        }
        res.send('Usuario eliminado correctamente.');
    });
});

// Actualizar examen
app.post('/update-exam', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    const { id, title, topic, description_, level, content } = req.body;

    console.log("Datos recibidos para actualizar:", req.body);

    // Verificar que la estructura del contenido es correcta
    if (!content || !content.preguntas || !Array.isArray(content.preguntas) || content.preguntas.length === 0) {
        console.error("Estructura de contenido inválida:", content);
        return res.status(400).json({ error: "Invalid content structure" });
    }

    const examData = content; // El contenido del examen en formato JSON

    const updateQuery = 'UPDATE exams_json SET title = ?, topic = ?, description_ = ?, level = ?, exam_data = ? WHERE id = ?';
    connection.query(updateQuery, [title, topic, description_, level, JSON.stringify(examData), id], (err, results) => {
        if (err) {
            console.error('Error al actualizar el examen:', err);
            return res.status(500).json({ error: 'Error al actualizar el examen' });
        }

        res.json({ message: 'Examen actualizado correctamente' });
    });
});

app.listen(8080, () => console.log("Server started on http://localhost:8080"));
