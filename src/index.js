import { v4 as uuid } from "uuid";
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import joi from "joi";
dotenv.config();
import { connection } from "./db.js";
import bcrypt from "bcryptjs";

import { nanoid } from "nanoid";

const server = express();
server.use(express.json());
server.use(cors());

//SECTION - Unauthenticated Routes

const cadSchema = joi.object({
	name: joi.string().required(),
	email: joi.string().email().required(),
	password: joi.string().required(),
	confirmpassword: joi.ref("password"),
});
server.post("/signup", async (req, res) => {
	const { name, email, password, confirmpassword } = req.body;
	console.log(name, email, password);

	const validation = cadSchema.validate(name, {
		abortEarly: false,
	});
	if (validation.error) {
		validation.error.details.map((error) => error.message);
		return res.sendStatus(422);
	}
	try {
		const query = await connection.query(
			`
			SELECT * FROM user WHERE email = $1
		`,
			[email]
		);
		if (query) {
			return res.status(409);
		}

		const passwordEncrypted = bcrypt.hashSync(password, 10);
		console.log(passwordEncrypted);
		await connection.query(
			`
			INSERT INTO user (name, email, passwordEncrypted)
			VALUES ($1, $2, $3)
		`,
			[name, email, passwordEncrypted]
		);

		res.sendStatus(201);
	} catch (error) {
		console.error(error);
	}
});

const loginSchema = joi.object({
	email: joi.string().required(),
	password: joi.string().required(),
});
server.post("/singin", async (req, res) => {
	const { email, password } = req.body;
	const validation = loginSchema.validate(req.body, {
		abortEarly: false,
	});
	if (validation.error) {
		validation.error.details.map((error) => error.message);
		return res.sendStatus(422);
	}

	try {
		const query = await connection.query(
			`
			SELECT * FROM user
			WHERE email = "$1";
			`,
			[email]
		);
		if (query) {
			res.sendStatus(401);
		}

		const validatePassword = await bcrypt.compareSync(query.password, password);
		if (validatePassword) {
			const token = uuid();
			await connection.query(
				`
				INSERT INTO session (userId, token) 
				VALUES ("$1", "$2");
				`,
				[query.id, token]
			);
			res.sendStatus(200).send({ token: token });
		} else {
			res.sendStatus(401);
		}
	} catch (error) {
		console.error(error);
	}
});

server.get("/urls/:id", async (req, res) => {
	const id = req.params.id;
	try {
		const query = await connection.query(
			`
			SELECT * FROM shorted 
			WHERE "linkShorted" = $1
		`,
			[id]
		);
		if (!query) {
			res.sendStatus(404);
		}
		const result = await connection.query(
			`
			SELECT * FROM shorted WHERE "linkShorted" = $1 JOIN 
			links ON "linkShorted"."linkId" = links.id ;
		`,
			[id]
		);
		res.sendStatus(200).send(result.rows);
	} catch (error) {
		console.error(error);
	}
});

server.get("/urls/open/:shortUrl", async (req, res) => {
	const id = req.params.id;
	try {
		const query = await connection.query(
			`
			SELECT * FROM shorted 
			WHERE "linkShorted" = $1
		`,
			[id]
		);
		if (!query) {
			res.sendStatus(404);
		}
		const result = await connection.query(
			`
			SELECT * FROM shorted 
			WHERE "linkShorted" = $1 
			JOIN links ON "linkShorted"."linkId" = links.id
		`,
			[id]
		);
		res.redirect(302, result.row);
	} catch (error) {
		console.error(error);
	}
});

server.get("/ranking", async (req, res) => {});

//SECTION - Auth routes

server.post("/urls/shorten", async (req, res) => {
	const { authorization } = req.header;
	const token = authorization?.replace("Bearer ", "");
	const { url } = req.body;

	if (!token || !url) return res.sendStatus(401);

	try {
		//TODO - nanoid
	} catch (error) {
		console.error(error);
	}
});

server.delete("/urls/:id", async (req, res) => {
	const { authorization } = req.header;
	const token = authorization?.replace("Bearer ", "");
	if (!token) return res.sendStatus(401);

	const url = req.params.url;

	try {
		const user = await connection.query(
			`
			SELECT "userId" FROM session 
			WHERE session.token = $1
		`,
			[token]
		);

		const link = await connection.query(
			`
			SELECT "userId" FROM shorted 
			WHERE "linkShorted" = $1;
			`,
			[url]
		);

		if (!user || !link) {
			return res.sendStatus(404);
		}

		if (user === link) {
			await connection.query(
				`
				DELETE FROM links 
				WHERE shorted."linkId" = "urlId"
				AND
				DELETE FROM shorted 
				WHERE "linkShorted" = $1;
			`,
				[url]
			);
			return res.sendStatus(204);
		} else {
			return res.sendStatus(401);
		}
	} catch (error) {
		console.error(error);
	}
});

server.get("/users/me", async (req, res) => {
	const { authorization } = req.header;
	const token = authorization?.replace("Bearer ", "");
	if (!token) return res.sendStatus(401);

	try {
		const session = await connection.query(
			`
			SELECT session."userId" FROM session 
			WHERE token = $1 ;
		`,
			[token]
		);
		if (!session) {
			res.sendStatus(404);
		}

		const user = await connection.query(
			`
			SELECT 
				user.name,
				COUNT(links."userId")
			FROM session 
			WHERE user.id = $1 
			JOIN user ON session."userId" = user.id;
		`,
			[session.userId]
		);

		res.sendStatus(200);
	} catch (error) {
		console.error(error);
	}
});

server.get("/status", (req, res) => {
	res.sendStatus(200).send({ status: "OK" });
});

server.listen(process.env.PORT, () => {
	console.log("listening on port " + process.env.PORT);
});
