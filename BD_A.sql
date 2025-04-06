CREATE DATABASE BD_A;
USE  BD_A;

CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,  -- Almacenaremos el hash, no la contraseña en texto plano
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE usuario (
    id INT PRIMARY KEY AUTO_INCREMENT,
    nombre VARCHAR(100) NOT NULL,
	nombre2 VARCHAR(100) NOT NULL,
    nombre3 VARCHAR(100) NOT NULL,
    nombre4 VARCHAR(100) NOT NULL,
    nombre5 VARCHAR(100) NOT NULL,
    nombre6 VARCHAR(100) NOT NULL,
    nombre7 VARCHAR(100) NOT NULL,
    nombre8 VARCHAR(100) NOT NULL
);
INSERT INTO usuarios (username, password) VALUES ('admin1', '$2a$12$yKO0TFjF.unv/eBb8bkfpuhpNytOVKumYUgZBB0Bl0uByMqZ.N.gK');


select * from usuarios;