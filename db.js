
const mysql = require("mysql2/promise");

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '10028mike.',
    database: 'E-Voting System',
});

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

export default connection;
