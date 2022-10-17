import pg from "pg";
import dotenv from "dotenv";
dotenv.config();
 
const { Pool } = pg;

const connection = new Pool({
	user: "postgres",
	password: "123456",
	host: "localhost",
	port: 5432,
	database: "shortly",
});

export default connection;
