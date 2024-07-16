//INDEX for GENUIZ
const OpenAI = require("openai");  //importo la libreria de openai
const path = require('path'); //importo path
const express = require('express'); //importo express
const bodyParser = require('body-parser'); //importo body-parser
const cors = require('cors');  //importo cors

const app = express(); //creo la app
const port = 3000; //creo el puerto

//middelwares
app.use(cors());    //uso cors
app.use(express.json()); //para parsear JSON
app.use(bodyParser.json()); //uso body-parser
app.use(bodyParser.urlencoded({ extended: true })); //uso body-parser

require('dotenv').config();
//esto es para que se pueda leer el archivo .env

//nueva conexion con open ai y lo voy a igualar a un objeto
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
})

//función asincrona 
async function main() {
    // Servir archivos estáticos desde la carpeta public
    app.use(express.static('views'));
    app.use(express.json()); //uso json

    // Ruta para manejar la petición POST
    app.post('/recibir-datos', async (req, res) => {
        if (!req.body || !req.body.miDato) {  //si no hay un mensaje en el body
            return res.status(400).json({ error: "Bad Request or missing request" }); //devuelvo un error
        }
        console.log('Dato recibido:', req.body.miDato);  // Accedemos al dato enviado como JSON

        let miDato = req.body.miDato; //el mensaje que viene del body

        let messages = [{ role: "user", content: miDato }]; //  el mensaje que viene del usuario

        try { //intento hacer una petición a la api de openai
            const completion = await openai.chat.completions.create({ //creo una conversación
                model: "gpt-3.5-turbo", //modelo
                messages: messages //mensajes
            });

            let botResponse = completion.choices[0].message; //la respuesta del bot

            res.json({ //devuelvo un json con el mensaje
                botResponse
            });

            console.log('Respuesta del bot:', botResponse); //imprimo en consola la respuesta del bot

        } catch { //si hay un error
            console.error("Error form openai api", error); //imprimo en consola
            res.status(500).json({ error: "Internal Server Error" }) //devuelvo un error

        }

    });

    const sqlite3 = require('sqlite3').verbose();
    let db = new sqlite3.Database('./my_database.db', (err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log('Connected to the database.');
            db.run(`CREATE TABLE IF NOT EXISTS exams(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    data TEXT
                  )`,
                (err) => {
                    if (err) {
                        console.error(err.message);
                    } else {
                        console.log("Exams table created successfully");
                    }
                });
        }
    });

    app.use(express.json()); // Para poder parsear JSON en las solicitudes entrantes

    // Ruta para obtener un examen por ID
    app.get('/get-exams', (req, res) => {
        db.all(`SELECT data FROM exams`, [], (err, rows) => {
            if (err) {
                console.error(err.message);
                res.status(500).send(err);
            } else {
                res.status(200).send(rows);
            }
        });
    });

    //endpoint to save the exam
    app.post('/save-exam', (req, res) => {
        let examData = req.body.data; //now we have the data
        db.run(`INSERT INTO exams(data) VALUES(?)`, [examData], function (err) {
            if (err) {
                console.error(err.message);
                res.status(500).send(err);
            } else {
                console.log(examData);
                console.log(`A row has been inserted with row id ${this.lastID}`);
                res.status(200).send({ id: this.lastID });
            }
        });
    });

    // path to obtain the examn by the button id
    app.get('/get-exam', (req, res) => {
        const examId = req.query.id;

        db.get(`SELECT * FROM exams WHERE id = ?`, [examId], (err, row) => {
            if (err) {
                console.error(err.message);
                res.status(500).send(err);
            } else {
                if (row) {
                    res.status(200).send(row);
                } else {
                    res.status(404).send({ message: 'Examen no encontrado' });
                }
            }
        });
    });

    //endpoint to delete an examn
    app.delete('/delete-exam', (req, res) => {
        const examId = req.query.id;
        const sql = `DELETE FROM exams WHERE id = ?`;
        console.log(examId, sql);
        db.run(sql, [examId], function (err) {
            if (err) {
                console.error(err.message);
                res.status(500).send(err);
            } else {
                console.log(`Row(s) deleted ${this.changes}`);
                // Después de eliminar la fila, reordena los ID de las filas restantes
                const updateSql = `
                    UPDATE exams
                    SET id = id - 1
                    WHERE id > ?
                `;
                db.run(updateSql, [examId], function (err) {
                    if (err) {
                        console.error(err.message);
                        res.status(500).send(err);
                    } else {
                        console.log(`Row(s) updated ${this.changes}`);
                        // Después de actualizar los ID, vuelve a cargar los datos de la base de datos
                        db.all('SELECT * FROM exams', (err, rows) => {
                            if (err) {
                                console.error(err.message);
                                res.status(500).send(err);
                            } else {
                                // Envía los datos actualizados a la interfaz de usuario
                                res.status(200).send(rows);
                            }
                        });
                    }
                });
            }
        });
    });


    // Ruta para manejar la petición POST
    app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
    });

}

main() //llamo a la función main