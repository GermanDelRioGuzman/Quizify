const { createClient } = require('@supabase/supabase-js');

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
const { GoogleGenerativeAI } = require("@google/generative-ai");

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const app = express();
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('secreto'));
app.use(flash());
app.use(express.static("public"));

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
//  console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET);

//Conexión a la base de datos
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);


// Configuración estrategia local de Passport
passport.use(new PassportLocal(async function (username, password, done) {
    try {
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*, role:role_id(role_name)') // Asegurarse de incluir el role_name
            .eq('username', username)
            .single();

        if (userError) {
            console.error('Error al recuperar el usuario:', userError);
            return done(userError);
        }

        if (!user) {
            return done(null, false, { message: 'Usuario no encontrado' });
        }

        // Verificar contraseña
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return done(null, false, { message: 'Contraseña incorrecta' });
        }

        // Si el usuario no tiene rol, forzar a completar el registro
        if (!user.role_id || !user.role) {
            console.log('Usuario sin rol, redirigiendo a completar-registro');
            return done(null, user, { message: 'complete' }); // Marcar como "registro incompleto"
        }

        // Autenticación exitosa
        return done(null, user);
    } catch (err) {
        console.error('Error inesperado en la autenticación:', err);
        return done(err);
    }
}));


// Configuración  Google  login
passport.use('google-login', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/google/callback/login"
},

function(token, tokenSecret, profile, done) {
    supabase 
        .from('users')
        .select('*')
        .eq('google_id', profile.id)
        .single()
        .then(({data: user, error}) => {
            if (error) {
                return done(error);
            }

            if (!user) {
                return done(null, false, { message: 'Usuario no encontrado' });
            }

            if(user.role_id == null){
                return done(null, false, {message: 'complete'});

            }
            return done(null,user);
        })
        .catch(err =>{
            return done(err);
        });
}));


// Configuración  Google registro
passport.use('google-register', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/google/callback/register"
},
function(token, tokenSecret, profile, done) {
    supabase
        .from('users')
        .select('*')
        .eq('google_id', profile.id)
        .single()
        .then(({data: user, error}) => {
            if (error){
                return done(error);
            }
            if (user){
                return done(null, false, {message: 'userexists'});
            } else {
                supabase
                    .from('users')
                    .insert([
                        {
                            google_id: profile.id,
                            username: profile.emails[0].value,
                            name: profile.displayName,
                            role_id: null
                        }
                    ])
                    .select('*') // Ensure we retrieve inserted data
                    .then(({ data: newUser, error }) => {
                        if (error) {
                            return done(error);
                        }
        
                        if (!newUser || newUser.length === 0) {
                            return done(new Error('User not created'));
                        }
        
                        const createdUser = {
                            id: newUser[0].id,
                            username: profile.emails[0].value,
                            name: profile.displayName,
                            role_id: null
                        };
        
                        return done(null, createdUser);
                    })
                    .catch(err => {
                        return done(err);
                    });
            }
        })
        
        .catch(err => {
            return done(err);
        });
}));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    supabase
        .from('users') // Tabla de usuarios
        .select('*, role:role_id(role_name)') // Seleccionamos todos los campos de users y role_name de la tabla role
        .eq('id', id) // Filtramos por el id del usuario
        .single() // Aseguramos que solo obtenemos un resultado
        .then(({ data, error }) => {
            if (error) {
                console.error('Error en deserializeUser:', error);
                return done(error); // Si ocurre un error en la consulta, lo pasamos al callback
            }
            if (!data) {
                console.error('Usuario no encontrado en deserializeUser');
                return done(new Error('Usuario no encontrado'), null); // Si no encontramos el usuario
            }
            console.log("Usuario deserializado:", JSON.stringify(data, null, 2));
            // Devolvemos el primer (y único) resultado que es el usuario con el rol
            done(null, data);
        })
        .catch(err => {
            console.error('Error inesperado en deserializeUser:', err);
            done(err); // Si hay un error inesperado
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
        const userRole = req.user?.role?.role_name; // ✅ Acceder correctamente al rol

        console.log("Rol del usuario:", userRole, "| Rol requerido:", role);

        if (req.isAuthenticated() && userRole === role) {
            return next();
        }

        res.sendStatus(403);
    }
}


// Ruta principal
app.get('/', (req, res) => {
    console.log("Usuario en sesión:", JSON.stringify(req.user, null, 2));
    if (req.isAuthenticated()) {
        const userRole = req.user.role ? req.user.role.role_name : null;
        // Redirigir a diferentes vistas según el rol del usuario
        if (userRole === 'student') {
            res.redirect('/vistaEstudiante.html');
        } else if (userRole === 'teacher') {
            res.redirect('/vistaProfesor.html');
        } else {
            console.error('Rol no reconocido:', userRole);
            res.status(400).send('Rol no reconocido');
        }
    } else {
        // Usuario no autenticado: servir index.html
        res.sendFile(path.join(__dirname, 'src', 'views', 'index.html'));
    }
});

// Ruta para iniciar sesión
app.get("/iniciosesion", (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'iniciosesion.html'));
});

app.post("/iniciosesion", (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            console.error('Error en la autenticación:', err);
            return next(err);
        }
    
        if (!user) {
            console.log("No se encontró el usuario:", info);
            return res.redirect('/iniciosesion?error=auth');
        }

        console.log("Usuario autenticado:", JSON.stringify(user, null, 2)); // ✅ Imprime de forma legible

    
        req.logIn(user, (err) => {
            if (err) {
                console.error('Error al iniciar sesión:', err);
                return next(err);
            }
            console.log("Usuario tras iniciar sesión:", JSON.stringify(req.user, null, 2));

    
            // Redirigir a la vista correspondiente dependiendo del rol
            if(user.role_id == null){
                return res.redirect('/completar-registro');
            }else if (user.role.role_name === 'student') {
                return res.redirect('/vistaEstudiante.html');
            } else if (user.role.role_name === 'teacher') {
                return res.redirect('/vistaProfesor.html');
            } else {
                console.error('Rol no reconocido:', user.role.role_name);
                return res.status(400).send('Rol no reconocido');
            }


        });
    })(req, res, next);
    
});




// Ruta para registrarse
app.get("/registrarme", (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'registrarme.html'));
});

app.post("/registrarme", async (req, res, next) => {
    const { name, username, password, role } = req.body;

    console.log('Datos recibidos para registro:', req.body);

    // Verificar si el usuario ya existe
    const { data: existingUser, error: checkError } = await supabase
        .from('users')
        .select('id')
        .eq('username', username);

    if (checkError) {
        console.error('Error al verificar si el usuario existe:', checkError);
        return res.status(500).send('Error interno del servidor');
    }

    if (existingUser.length > 0) {
        return res.status(400).send('El nombre de usuario ya está en uso');
    }

    // Cifrar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    let role_id = null;
    if (role) {
        try {
            const { data: roleData, error: roleError } = await supabase
                .from('role')
                .select('id')
                .eq('role_name', role)
                .single();

            if (roleError || !roleData) {
                console.error('Error al obtener el ID del rol:', roleError);
                return res.status(400).send('Rol no válido');
            }

            role_id = roleData.id;
        } catch (err) {
            console.error('Unexpected error:', err);
            return res.status(500).send('Error interno del servidor');
        }
    }

    // Insertar el nuevo usuario
    const { data, error } = await supabase
        .from('users')
        .insert([
            {
                name,
                username,
                password: hashedPassword,
                role_id // Este valor debe ser válido o NULL
            }
        ])
        .select('*');

    if (error) {
        console.error('Error al registrar el usuario:', error);
        return res.status(500).send('Error interno del servidor');
    }

    // Si el usuario no tiene rol, enviarlo a completar registro
    if (!role_id) {
        return res.redirect('/completar-registro');
    }

    res.redirect('/iniciosesion');
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

app.post('/completar-registro', ensureAuthenticated, async (req, res) => {
    const { role } = req.body;
    const userId = req.user.id;

    try {
        // Buscar el role_id correspondiente al role_name
        const { data: roleData, error: roleError } = await supabase
            .from('role')  
            .select('id')
            .eq('role_name', role)
            .single();  

        if (roleError || !roleData) {
            console.error('Error al obtener role_id o rol no encontrado');
            return res.redirect('/completar-registro?error=rolename'); 
        }

        const role_id = roleData.id;

        // Actualizar el role_id del usuario en la tabla 'users'
        const { error: updateError } = await supabase
            .from('users')
            .update({ role_id })
            .eq('id', userId);

        if (updateError) {
            console.error('Error al actualizar el rol del usuario:', updateError);
            return res.redirect('/completar-registro?error=update');  
        }

        // Actualizar el rol en el objeto de usuario en la sesión
        req.user.role_id = role_id;

        // Obtener el nombre del rol (role_name) para actualizarlo en la sesión
        const { data: roleNameData, error: roleNameError } = await supabase
            .from('role')  
            .select('role_name')
            .eq('id', role_id)
            .single();
        
        if (roleNameError || !roleNameData) {
            console.error('Error al obtener el nombre del rol:', roleNameError);
            return res.redirect('/completar-registro?error=rolename');  
        }

        // Actualizar el nombre del rol en el objeto de usuario en la sesión
        req.user.role_name = roleNameData.role_name;

        // Redirigir al usuario a la vista correcta
        switch (req.user.role_name.toLowerCase()) {
            case 'teacher':
                return res.redirect('/vistaProfesor.html');
            case 'student':
                return res.redirect('/vistaEstudiante.html');
            default:
                return res.status(400).send('Rol no reconocido');
        }
    } catch (error) {
        console.error('Error al completar el registro:', error);
        return res.redirect('/completar-registro?error=general');
    }
});



// Rutas para vistas específicas según el rol
app.get('/vistaEstudiante.html', ensureAuthenticated, ensureRole('student'), (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'views', 'vistaEstudiante.html'));
});

app.get('/vistaProfesor.html', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    console.log("Usuario en sesión al acceder a /vistaProfesor:", JSON.stringify(req.user, null, 2));
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
        const model = genAI.getGenerativeModel({ model: "gemini-pro" });
        const result = await model.generateContent(miDato);
        let botResponse = result.response.text();

        console.log("Respuesta de Gemini:", botResponse);

        // Validar la estructura del JSON
        botResponse = botResponse.replace(/```json/g, "").replace(/```/g, "").trim();
        let parsedResponse = JSON.parse(botResponse);

        try {
            parsedResponse = JSON.parse(botResponse);
        } catch (error) {
            console.error("Error al parsear la respuesta JSON:", error);
            return res.status(500).json({ error: "Invalid JSON format from Gemini" });
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
        console.error("Error from Gemini API", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.post('/save-exam', ensureAuthenticated, ensureRole('teacher'), async (req, res) => {
    const { title, topic, description, level, content } = req.body;
    const teacher_id = req.user.id;

    console.log("Usuario autenticado:", req.user);
    console.log("Datos recibidos para guardar:", req.body);

    if (!content || !content.preguntas || !Array.isArray(content.preguntas) || content.preguntas.length === 0) {
        console.error("Estructura de contenido inválida:", content);
        return res.status(400).json({ error: "Invalid content structure" });
    }

    let examData;
    try {
        // 🔍 **Validar si el JSON es correcto antes de guardarlo**
        console.log("🔍 JSON original recibido:", content);
        examData = JSON.stringify(content);
        console.log("✅ JSON convertido antes de guardar:", examData);
    } catch (err) {
        console.error("❌ Error al serializar JSON:", err);
        return res.status(500).json({ error: "Error al procesar JSON antes de guardar" });
    }

    const examCode = Math.random().toString(36).substring(2, 10).toUpperCase();

    try {
        const { data, error } = await supabase
            .from('exams_json')
            .insert([
                {
                    teacher_id,
                    title,
                    topic,
                    description,
                    level,
                    exam_code: examCode,
                    exam_data: examData  // ✅ Asegurar que sea JSON
                }
            ])
            .select();

        if (error) {
            console.error('❌ Error al guardar en Supabase:', error);
            return res.status(500).json({ error: 'Error al guardar en Supabase' });
        }

        console.log("✅ Examen guardado correctamente en Supabase:", data);
        res.json({ message: 'Examen guardado correctamente', id: data[0].id, accessCode: examCode });
    } catch (err) {
        console.error('❌ Error inesperado al guardar el examen:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});



app.get('/get-exams-json', ensureAuthenticated, ensureRole('teacher'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('exams_json')
            .select('id, title, topic, level, exam_code, exam_data')
            .eq('teacher_id', req.user.id);

        if (error) {
            console.error('❌ Error al obtener los exámenes desde Supabase:', error);
            return res.status(500).json({ error: 'Error al obtener los exámenes' });
        }

        console.log("✅ Datos obtenidos de Supabase:", data);

        res.json(data);
    } catch (err) {
        console.error('❌ Error inesperado al obtener los exámenes:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});



app.get('/get-exams-json', ensureAuthenticated, ensureRole('teacher'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('exams_json')
            .select('*')
            .eq('teacher_id', req.user.id);

        if (error) {
            console.error('Error al obtener los exámenes:', error);
            return res.status(500).json({ error: 'Error al obtener los exámenes' });
        }

        res.json(data);
    } catch (err) {
        console.error('Error inesperado:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
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




// Ruta para guardar el resultado del examen
app.post('/save-exam-result', ensureAuthenticated, ensureRole('student'), async (req, res) => {
    const { examId, finalScore } = req.body;
    const userId = req.user.id;

    try {
        // Insert the exam result into Supabase
        const { data, error } = await supabase
            .from('exam_results')
            .insert([
                {
                    user_id: userId,
                    exam_id: examId,
                    score: finalScore
                }
            ])
            .select(); // Optional: Return inserted data

        if (error) {
            console.error('Error al guardar el resultado del examen en Supabase:', error);
            return res.status(500).json({ error: 'Error al guardar el resultado del examen' });
        }

        res.json({ message: 'Resultado guardado correctamente', result: data });
    } catch (err) {
        console.error('Error inesperado al guardar el resultado:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


// Actualiza la ruta de vistaProfesor.html para mostrar los resultados
app.get('/get-exam-results', ensureAuthenticated, ensureRole('teacher'), async (req, res) => {
    const examId = req.query.examId;

    try {
        // Consulta a Supabase para obtener los resultados del examen con el usuario correspondiente
        const { data, error } = await supabase
            .from('exam_results') // Tabla de resultados de exámenes en Supabase
            .select('*, user:user_id(username, name)') // Incluye información del usuario
            .eq('exam_id', examId); // Filtrar por exam_id

        if (error) {
            console.error('❌ Error al obtener los resultados desde Supabase:', error);
            return res.status(500).json({ error: 'Error al obtener los resultados' });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({ error: 'No hay resultados para este examen' });
        }

        res.json(data);
    } catch (err) {
        console.error('❌ Error inesperado al obtener los resultados:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


// Prueba para ver los datos del profe
app.get('/get-profesor-info', ensureAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;

        // Consulta a Supabase
        const { data, error } = await supabase
            .from('users')
            .select('name, username')
            .eq('id', userId)
            .single(); // Asegura que solo devuelve un resultado

        if (error) {
            console.error('Error al obtener la información del profesor:', error);
            return res.status(500).json({ error: 'Error al obtener la información del profesor' });
        }

        if (!data) {
            return res.status(404).json({ error: 'Profesor no encontrado' });
        }

        res.json(data); // Devuelve el objeto con `name` y `username`
    } catch (err) {
        console.error('Error inesperado al obtener el profesor:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

  
// Prueba para ver los datos del estudiante
app.get('/get-student-info', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;

    try {
        // Consulta a Supabase para obtener la información del estudiante
        const { data, error } = await supabase
            .from('users') // Tabla de usuarios en Supabase
            .select('name, username') // Seleccionar solo los campos necesarios
            .eq('id', userId) // Filtrar por ID del usuario
            .single(); // Asegura que solo devuelve un resultado único

        if (error) {
            console.error('❌ Error al obtener la información del estudiante desde Supabase:', error);
            return res.status(500).json({ error: 'Error al obtener la información del estudiante' });
        }

        if (!data) {
            return res.status(404).json({ error: 'Estudiante no encontrado' });
        }

        res.json(data);
    } catch (err) {
        console.error('❌ Error inesperado al obtener la información del estudiante:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


// Obtener resultados del estudiante
app.get('/get-student-results', ensureAuthenticated, ensureRole('student'), async (req, res) => {
    const userId = req.user.id;

    try {
        // Realiza la consulta a Supabase con un JOIN implícito
        const { data, error } = await supabase
            .from('exam_results')
            .select(`
                exam_id,
                score,
                timestamp,
                exams_json!fk_exam(title, topic, exam_code),
                users(name)
            `)
            .eq('user_id', userId);

        if (error) {
            console.error('❌ Error al obtener los resultados del estudiante:', error);
            return res.status(500).json({ error: 'Error al obtener los resultados del estudiante' });
        }

        if (!data || data.length === 0) {
            return res.json([]); // Devuelve un array vacío si no hay resultados
        }

        // Formatear los resultados para que coincidan con la estructura original
        const formattedResults = data.map(result => ({
            exam_id: result.exam_id,
            score: result.score,
            timestamp: result.timestamp,
            title: result.exams_json?.title || 'Título no disponible',
            topic: result.exams_json?.topic || 'Tema no disponible',
            exam_code: result.exams_json?.exam_code || 'Código no disponible',
            professor_name: result.users?.name || 'Profesor desconocido'
        }));

        res.json(formattedResults);
    } catch (err) {
        console.error('❌ Error inesperado al obtener los resultados del estudiante:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Verificar si un examen ya ha sido respondido por el estudiante
app.get('/check-exam-result', ensureAuthenticated, ensureRole('student'), async (req, res) => {
    const examId = req.query.examId;
    const userId = req.user?.id; // Ensure user ID is retrieved

    // ✅ Check if both `examId` and `userId` are defined and are numbers
    if (!examId || isNaN(examId)) {
        return res.status(400).json({ error: 'Invalid or missing examId' });
    }
    if (!userId || isNaN(userId)) {
        return res.status(400).json({ error: 'Invalid or missing userId' });
    }

    try {
        const { data, error } = await supabase
            .from('exam_results')
            .select('exam_id, score, timestamp, exams_json!fk_exam(title, topic, exam_code)')
            .eq('exam_id', examId)
            .eq('user_id', userId);

        if (error) {
            console.error('Error al verificar el resultado del examen:', error);
            return res.status(500).json({ error: 'Error al verificar el resultado del examen' });
        }

        if (data.length > 0) {
            res.json({ alreadyTaken: true, examResult: data[0] });
        } else {
            res.json({ alreadyTaken: false });
        }
    } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// Obtener un examen a través del código
app.get('/get-exam-by-code', ensureAuthenticated, ensureRole('student'), async (req, res) => {
    const examCode = req.query.code;

    try {
        // Consulta en Supabase para obtener el examen con el código proporcionado
        const { data, error } = await supabase
            .from('exams_json') // Nombre de la tabla en Supabase
            .select('exam_data')  // Seleccionamos todos los campos
            .eq('exam_code', examCode)
            .single();  // Asegura que solo obtenga un único resultado

        if (error) {
            console.error('❌ Error al obtener el examen desde Supabase:', error);
            return res.status(500).json({ error: 'Error al obtener el examen' });
        }

        if (!data) {
            return res.status(404).json({ error: 'Examen no encontrado' });
        }

        res.json(data);
    } catch (err) {
        console.error('❌ Error inesperado al obtener el examen:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


// Guardar el resultado del examen
app.post('/save-exam-result', ensureAuthenticated, ensureRole('student'), async (req, res) => {
    const { examId, finalScore } = req.body;
    const userId = req.user?.id; // Ensure user ID is retrieved

    // ✅ Validate the input
    if (!examId || isNaN(examId)) {
        return res.status(400).json({ error: 'Invalid or missing examId' });
    }
    if (!userId || isNaN(userId)) {
        return res.status(400).json({ error: 'Invalid or missing userId' });
    }
    if (finalScore === undefined || finalScore === null || isNaN(finalScore)) {
        return res.status(400).json({ error: 'Invalid or missing finalScore' });
    }

    try {
        // ✅ Insert into Supabase
        const { data, error } = await supabase
            .from('exam_results') // Name of the table in Supabase
            .insert([
                {
                    user_id: userId,
                    exam_id: examId,
                    score: finalScore,
                }
            ])
            .select(); // Return the inserted data

        // ❌ Handle errors
        if (error) {
            console.error('Error al guardar el resultado del examen en Supabase:', error);
            return res.status(500).json({ error: 'Error al guardar el resultado del examen en Supabase' });
        }

        // ✅ Success response
        res.json({ message: 'Resultado guardado correctamente', result: data[0] });

    } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Obtener un examen por ID
app.get('/get-exam-by-id', ensureAuthenticated, ensureRole('student'), async (req, res) => {
    const examId = req.query.id;

    try {
        // Consulta a Supabase para obtener el examen por ID
        const { data, error } = await supabase
            .from('exams_json') // Nombre de la tabla en Supabase
            .select('*') // Seleccionar todos los campos
            .eq('id', examId) // Filtrar por el ID del examen
            .single(); // Asegurar que solo devuelve un resultado único

        if (error) {
            console.error('❌ Error al obtener el examen desde Supabase:', error);
            return res.status(500).json({ error: 'Error al obtener el examen' });
        }

        if (!data) {
            return res.status(404).json({ error: 'Examen no encontrado' });
        }

        res.json(data);
    } catch (err) {
        console.error('❌ Error inesperado al obtener el examen:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


// Eliminar un usuario MANUALMENTE (o sea en la base de datos)
app.delete('/delete-user', ensureAuthenticated, async (req, res) => {
    const userId = req.query.id;

    try {
        // Eliminar usuario en Supabase
        const { error } = await supabase
            .from('users') // Tabla de usuarios en Supabase
            .delete()
            .eq('id', userId); // Filtra por el ID del usuario

        if (error) {
            console.error('❌ Error al eliminar el usuario en Supabase:', error);
            return res.status(500).json({ error: 'Error al eliminar el usuario.' });
        }

        res.json({ message: '✅ Usuario eliminado correctamente.' });
    } catch (err) {
        console.error('❌ Error inesperado al eliminar el usuario:', err);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


// Actualizar examen
app.post('/update-exam', ensureAuthenticated, ensureRole('teacher'), (req, res) => {
    const { id, title, topic, description, level, content } = req.body;

    console.log("Datos recibidos para actualizar:", req.body);

    // Verificar que la estructura del contenido es correcta
    if (!content || !content.preguntas || !Array.isArray(content.preguntas) || content.preguntas.length === 0) {
        console.error("Estructura de contenido inválida:", content);
        return res.status(400).json({ error: "Invalid content structure" });
    }

    const examData = content; // El contenido del examen en formato JSON

    const updateQuery = 'UPDATE exams_json SET title = ?, topic = ?, description_ = ?, level = ?, exam_data = ? WHERE id = ?';
    connection.query(updateQuery, [title, topic, description, level, JSON.stringify(examData), id], (err, results) => {
        if (err) {
            console.error('Error al actualizar el examen:', err);
            return res.status(500).json({ error: 'Error al actualizar el examen' });
        }

        res.json({ message: 'Examen actualizado correctamente' });
    });
});

app.listen(8080, () => console.log("Server started on http://localhost:8080"));
module.exports = app;