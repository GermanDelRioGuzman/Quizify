# GENUIZ


NOTA: Para correr los servers
- crear .env:
  
 OPENAI_API_KEY=" "

 GOOGLE_CLIENT_ID= 
 
 GOOGLE_CLIENT_SECRET=


- correr app.js

-> Asegurense de tener instalados:

  -  npm install dotenv express passport cookie-parser express-session passport-local passport-google-oauth20 mysql bcrypt connect-flash
  -  

NOTA: Para probarlo creen las siguientes tablas en MySQL:

```sql
CREATE DATABASE genuiz;
USE genuiz;

CREATE TABLE role (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name ENUM('student', 'teacher') NOT NULL
);

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NULL,
    role_id INT NULL,
    google_id VARCHAR(255) NULL,
    FOREIGN KEY (role_id) REFERENCES role(id)
);

CREATE TABLE IF NOT EXISTS exams_json (
    id INT AUTO_INCREMENT PRIMARY KEY,
    teacher_id INT NOT NULL,
    title VARCHAR(50) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    description_ VARCHAR(255) NULL,
    level ENUM('facil', 'medio', 'dificil') NULL,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exam_code VARCHAR(50) UNIQUE NOT NULL,
    exam_data JSON,
    FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS exam_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    exam_id INT NOT NULL,
    score DECIMAL(5,2) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (exam_id) REFERENCES exams_json(id) ON DELETE CASCADE
);


  
