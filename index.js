const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const PORT = 3000;
const SECRET_KEY = "clave_secreta";

app.use(cors());
app.use(express.json());

// ========================================
// CONEXIÓN A POSTGRESQL
// ========================================

const pool = new Pool({
    host: "localhost",
    user: "postgres",
    database: "softjobs",
    port: 5432
});

pool.query("SELECT NOW()")
    .then(() => console.log("Conexión a PostgreSQL exitosa"))
    .catch((error) =>
        console.error("Error de conexión:", error.message)
    );


// ========================================
// MIDDLEWARE - REGISTRO DE CONSULTAS
// ========================================

const registrarConsulta = (req, res, next) => {
    console.log(
        `${new Date().toISOString()} - ${req.method} ${req.url}`
    );

    next();
};

app.use(registrarConsulta);


// ========================================
// MIDDLEWARE - VERIFICAR CREDENCIALES
// ========================================

const verificarCredenciales = (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email y password son obligatorios"
        });
    }

    next();
};


// ========================================
// MIDDLEWARE - VERIFICAR TOKEN JWT
// ========================================

const verificarToken = (req, res, next) => {
    try {
        const authorization = req.header("Authorization");

        if (!authorization) {
            return res.status(401).json({
                message: "Token no proporcionado"
            });
        }

        const token = authorization.replace("Bearer ", "");

        const decoded = jwt.verify(
            token,
            SECRET_KEY
        );

        req.email = decoded.email;

        next();

    } catch (error) {
        return res.status(401).json({
            message: "Token inválido"
        });
    }
};


// ========================================
// GET /
// ========================================

app.get("/", (req, res) => {
    res.send("Servidor Soft Jobs funcionando");
});


// ========================================
// POST /usuarios
// REGISTRAR USUARIO
// ========================================

app.post(
    "/usuarios",
    verificarCredenciales,
    async (req, res) => {

        try {
            const {
                email,
                password,
                rol,
                lenguage
            } = req.body;

            const passwordEncriptada =
                await bcrypt.hash(password, 10);

            const consulta = `
                INSERT INTO usuarios
                (email, password, rol, lenguage)
                VALUES ($1, $2, $3, $4)
                RETURNING id, email, rol, lenguage
            `;

            const values = [
                email,
                passwordEncriptada,
                rol,
                lenguage
            ];

            const { rows } = await pool.query(
                consulta,
                values
            );

            res.status(201).json(rows[0]);

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Error al registrar el usuario"
            });
        }
    }
);


// ========================================
// POST /login
// ========================================

app.post(
    "/login",
    verificarCredenciales,
    async (req, res) => {

        try {
            const { email, password } = req.body;

            const consulta =
                "SELECT * FROM usuarios WHERE email = $1";

            const { rows } = await pool.query(
                consulta,
                [email]
            );

            if (rows.length === 0) {
                return res.status(401).json({
                    message: "Email o contraseña incorrectos"
                });
            }

            const usuario = rows[0];

            const passwordCorrecta =
                await bcrypt.compare(
                    password,
                    usuario.password
                );

            if (!passwordCorrecta) {
                return res.status(401).json({
                    message: "Email o contraseña incorrectos"
                });
            }

            const token = jwt.sign(
                {
                    email: usuario.email
                },
                SECRET_KEY
            );

            res.json({
                token
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Error al iniciar sesión"
            });
        }
    }
);


// ========================================
// GET /usuarios
// USUARIO AUTENTICADO
// ========================================

app.get(
    "/usuarios",
    verificarToken,
    async (req, res) => {

        try {
            const consulta = `
                SELECT id, email, rol, lenguage
                FROM usuarios
                WHERE email = $1
            `;

            const { rows } = await pool.query(
                consulta,
                [req.email]
            );

            if (rows.length === 0) {
                return res.status(404).json({
                    message: "Usuario no encontrado"
                });
            }

            res.json(rows[0]);

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Error al obtener el usuario"
            });
        }
    }
);


// ========================================
// INICIAR SERVIDOR
// ========================================

app.listen(PORT, () => {
    console.log(
        `Servidor corriendo en http://localhost:${PORT}`
    );
});