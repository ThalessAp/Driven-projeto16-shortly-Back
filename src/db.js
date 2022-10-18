import pg from "pg";
import dotenv from "dotenv";
dotenv.config();

const { Pool } = pg;

const database = {
	connectionString: process.env.DATABASE_URL,
	ssl: {
		rejectUnauthorized: false
	}
};
	/* new Pool({
	user: "postgres",
	password: "123456",
	host: "127.0.0.1",
	port: 5432,
	database: "shortly",
}) ;
*/

const connection = new Pool(database);
export {connection};
