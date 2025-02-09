import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";  
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import path from 'path';
import multer from 'multer';
import { fileURLToPath } from 'url';
import moment from 'moment';
import cron  from 'node-cron';
import bodyParser from "body-parser";
import util from 'util';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();
import session from  'express-session';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';

const JWT_SECRET='waweru';

const app = express();
const PORT = process.env.PORT || 3000;


app.use(cookieParser());
app.use(session({
  secret: 'waweru',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true, // Ensure cookies are only sent over HTTPS
    httpOnly: true, // Prevent client-side script access to the cookie
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

// Enable CORS for all routes
app.use(cors({
    origin: ['http://localhost:5173'], // Allow your React app
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  
    credentials: true, // Allow credentials if needed
}));


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(express.json());



// Create MySQL connection
let db;
(async () => {
  try {
    // Use environment variables for connection configuration
    db = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
    });

    console.log('Connected to MySQL');
  } catch (error) {
    console.error('Error connecting to MySQL:', error);
  }
})();

app.get('/api/dashboard-stats', async (req, res) => {
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`;

  try {
    const [usersResult] = await db.query('SELECT COUNT(*) AS count FROM users');
    const [candidatesResult] = await db.query(`SELECT COUNT(*) AS count FROM ${schemaName}.candidates`);

    // Extract counts correctly
    const totalUsers = usersResult[0]?.count || 0;
    const totalCandidates = candidatesResult[0]?.count || 0;

    console.log('Total Users:', totalUsers);
    console.log('Total Candidates:', totalCandidates);

    res.json({
      totalUsers,
      totalCandidates,
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});




// Fetch schools from the database
app.get('/schools', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [schools] = await db.query('SELECT idschools, schoolname FROM schools');
 
    if (schools.length === 0) {
      return res.status(404).json({ message: 'No schools found' });
    }
    
    res.json(schools);
  } catch (error) {
    console.error('Error fetching schools:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
})
;
app.get('/api/allhouses', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [houses] = await db.query('SELECT id, house_name FROM houses');
 
    if (houses.length === 0) {
      return res.status(404).json({ message: 'No houses found' });
    }
    
    res.json(houses);
  } catch (error) {
    console.error('Error fetching Houses:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }

});
app.get('/houses', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [houses] = await db.query('SELECT * FROM houses');
 
    if (houses.length === 0) {
      return res.status(404).json({ message: 'No schools found' });
    }
    
    res.json(houses);
  } catch (error) {
    console.error('Error fetching schools:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/congresspersons', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [congresspersons] = await db.query('SELECT * FROM congresspersonroles');
 
    if (congresspersons.length === 0) {
      return res.status(404).json({ message: 'No schools found' });
    }
    
    res.json(congresspersons);
  } catch (error) {
    console.error('Error fetching schools:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/campuses', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [campuses] = await db.query('SELECT * FROM campuses');
 
    if (campuses.length === 0) {
      return res.status(404).json({ message: 'No schools found' });
    }
    
    res.json(campuses);
  } catch (error) {
    console.error('Error fetching schools:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
app.get('/departments/:schoolId', async (req, res) => {
    const { schoolId } = req.params;
  
    try {
      if (!db) {
        return res.status(500).json({ message: 'Database connection not available' });
      }
  
      const [departments] = await db.query('SELECT iddepartments, department_name FROM departments WHERE school_id = ?', [schoolId]);
      res.json(departments);
    } catch (error) {
      console.error('Error fetching departments:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });





  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: 'mikekariuki10028@gmail.com',
      pass: 'qvfk dcie sjop hcxb',
    },
  });


  app.post('/register', async (req, res) => {
    console.log('Incoming registration request:', req.body);
  
    const {
      name,
      admissionno,
      email,
      password,
      gender,
      department_id,
      school_id,
      residency_status,
      house_id,
      off_campus_address,
      campus,
      educationLevel,
      studentType,
      internationalStudent,
      disabled,
    } = req.body;
  
    if (
      !name || !admissionno || !email || !password || !gender ||
      !department_id || !school_id || !residency_status || !campus || !educationLevel || !studentType ||
      !internationalStudent || !disabled ||
      (residency_status === 'Resident' && !house_id) ||
      (residency_status === 'Non-Resident' && !off_campus_address)
    ) {
      console.log('Validation failed: Missing required fields');
      return res.status(400).json({ message: 'Validation failed: Missing required fields' });
    }
  
    try {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
  
      const intlStudentValue = internationalStudent === 'Yes' ? 1 : 0;
      const disabledValue = disabled === 'Yes' ? 1 : 0;
      const verificationToken = crypto.randomBytes(32).toString('hex');
  
      const result = await db.query(
        'INSERT INTO users (name, admissionno, email, password, gender, department, school, residency_status, hostel, off_campus_address, verificationToken, isVerified, campus, internationalstudent, disabled, student_type, education_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          name, admissionno, email, hashedPassword, gender, department_id,
          school_id, residency_status, house_id || null, off_campus_address || null,
          verificationToken, false, campus, intlStudentValue, disabledValue, studentType, educationLevel
        ]
      );
  
      const newUserId = result.insertId;
      console.log('New user inserted with ID:', newUserId);
  
      const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
      const verificationUrl = `http://localhost:5173/verify?token=${encodeURIComponent(token)}`;
  
      const mailOptions = {
        from: 'mikekariuki10028@gmail.com',
        to: email,
        subject: 'Verify Your Email',
        html: `<p>Thank you for registering! Please verify your email by clicking the link below:</p>
               <a href="${verificationUrl}">Verify Email</a>`,
      };
  
      await transporter.sendMail(mailOptions);
  
      console.log('Verification email sent to:', email);
      return res.status(201).json({ message: 'User registered successfully. Please check your email for verification.' });
    } catch (error) {
      console.error('Error during registration:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  });
  

  app.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).send('Verification token is missing.');
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(400).send('Invalid or expired verification token.');
    }

    const userEmail = decoded.email;

    try {
      const result = await db.query(
        'UPDATE users SET isVerified = 1 WHERE email = ?',
        [userEmail]
      );

      if (result[0].affectedRows === 0) {
        return res.status(404).send('User not found.');
      }

      res.send('Email successfully verified! You can now log in.');
    } catch (error) {
      console.error('Verification error:', error);
      res.status(500).send('Server error.');
    }
  });
});
app.get('/protected-route', (req, res) => {
  if (!req.session.token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  // Process the protected route
  res.status(200).json({ message: 'Welcome to the protected route' });
});


const loginLimiter = rateLimit({
  windowMs: 3 * 60 * 1000, 
  max: 5, 
  message: 'Too many login attempts. Please try again later.',
});

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    const [user] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    if (user.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const existingUser = user[0];

    // Check if the user is disabled
    if (existingUser.status_disabled) {
      return res.status(403).json({ message: 'Your account has been disabled. Please contact support.' });
    }

    if (!existingUser.isVerified) {
      return res.status(403).json({ message: 'Your account is not verified. Please verify your email to log in.' });
    }

    const passwordMatch = await bcrypt.compare(password, existingUser.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: existingUser.id, email: existingUser.email, role: existingUser.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    req.session.token = token;
    req.session.userId = existingUser.id;
    req.session.role = existingUser.role;

    return res.status(200).json({
      message: 'Login successful',
      token: token,
      role: existingUser.role,
    });
  } catch (error) {
    console.error('Error during login:', error.message);
    return res.status(500).json({ message: 'Server error' });
  }
});



app.post('/logout', (req, res) => {

  res.status(200).json({ message: 'Logout successful' });
});

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.sendStatus(403); // No token provided


  jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
          console.error("Token verification failed:", err.message);
          return res.sendStatus(403); // Invalid token
      }
      req.user = user;
      next(); // Proceed to the next middleware or route handler
  });
};


app.get('/api/user', authenticateToken, async (req, res) => {
    const userId = req.user.userId;

    try {
        const [user] = await db.execute('SELECT name, email FROM users WHERE id = ?', [userId]);

        if (user.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const userData = user[0];
        return res.status(200).json({
            name: userData.name,
            email: userData.email,
        });
    } catch (error) {
        console.error('Error fetching user data:', error.message);
        return res.status(500).json({ message: 'Server error' });
    }
});


app.get('/roles', async (req, res) => {
    try {
      const [roles] = await db.execute('SELECT * FROM roles');
      res.json(roles);
    } catch (error) {
      console.error('Error fetching roles:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });
  


app.get('/api/houses', async (req, res) => {
  try {
    const { gender } = req.query;
    let query = 'SELECT * FROM houses';
    const params = [];

    if (gender) {
      query += ' WHERE gender = ?';
      params.push(gender);
    }

    const [houses] = await db.query(query, params);

    res.status(200).json({
      success: true,
      data: houses,
    });
  } catch (error) {
    console.error('Error fetching houses:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch houses',
    });
  }
});




const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); 
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); 
  }
});

const upload = multer({ storage });


app.post('/candidate-register', upload.single('photo'), async (req, res) => {
  const {
    name,
    admissionNo,
    school,
    department,
    role,
    congresspersonType,
    gender,
    motto,
    hostel,
    year,
    residentStatus,
    disabilityStatus,
    campus
  } = req.body;

  const photoPath = req.file ? req.file.path : null;

  try {
    const sql = `
      INSERT INTO evoting_${year}.candidates (
        name, admission_no, school_id, department_id, role, congressperson_type, gender, motto, hostel, photo_path, is_approved, resident_status, disability_status, campus, approval_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await db.query(sql, [name, admissionNo, school, department, role, congresspersonType, gender, motto, hostel, photoPath, false, residentStatus, disabilityStatus, campus, null]);

    res.status(201).send('Candidate registered successfully');
  } catch (error) {
    console.error('Error inserting candidate:', error);
    res.status(500).send('Error inserting candidate');
  }
});



app.post('/api/approve-candidate/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const sql = 'UPDATE candidates SET is_approved = TRUE WHERE id = ?';
    await db.query(sql, [id]);
    res.status(200).send('Candidate approved successfully');
  } catch (error) {
    console.error('Error approving candidate:', error);
    res.status(500).send('Error approving candidate');
  }
});

app.post('/api/decline-candidate/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const sql = 'DELETE FROM candidates WHERE id = ?';
    await db.query(sql, [id]);
    res.status(200).send('Candidate declined successfully');
  } catch (error) {
    console.error('Error declining candidate:', error);
    res.status(500).send('Error declining candidate');
  }
});
app.get('/api/unapproved-candidates', async (req, res) => {
  try {
    const [unapprovedCandidates] = await db.query(
      'SELECT * FROM candidates WHERE is_approved = FALSE'
    );
    res.status(200).json(unapprovedCandidates);
  } catch (error) {
    console.error('Error fetching unapproved candidates:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


app.get('/userprofile', async (req, res) => {
  const email = req.query.email; // Get email from query parameter

  // Check if the email is provided
  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    // Use the email in the query, making sure it's a valid string
    const [user] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    // Check if user exists
    if (user.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const existingUser = user[0];

    // Exclude password or any sensitive data from response
    delete existingUser.password; // Optional: do not send the password

    return res.status(200).json({ user: existingUser });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error' });
  }
});



app.get('/api/getCongressPeopleByCampus', async (req, res) => {
  const email = req.query.email;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`;

  if (!email) {
    console.log('Error: Email is missing');
    return res.status(400).send('Email is required');
  }

  try {
    // Step 1: Fetch user data, including the campus ID
    const userQuery = `
      SELECT campus
      FROM users
      WHERE email = ?;
    `;
    const [userData] = await db.execute(userQuery, [email]);

    if (userData.length === 0) {
      console.log('No user found with email:', email);
      return res.status(404).send('User not found');
    }

    const { campus: campusId } = userData[0];

    // Step 2: Fetch the campus name using the campus ID
    const campusQuery = `
      SELECT name
      FROM campuses
      WHERE id = ?;
    `;
    const [campusData] = await db.execute(campusQuery, [campusId]);

    if (campusData.length === 0) {
      console.log('No campus found with ID:', campusId);
      return res.status(404).send('Campus not found');
    }

    const campusName = campusData[0].name;

    // Step 3: Fetch congresspeople by campus ID and role
    const congressPeopleQuery = `
      SELECT *
      FROM ${schemaName}.candidates
      WHERE congressperson_type = 5 AND campus = ?;
    `;
    const [congressPeople] = await db.execute(congressPeopleQuery, [campusId]);

    // Step 4: Fetch the user's vote
    const voteQuery = `
      SELECT candidate_id
      FROM ${schemaName}.full_votes
      WHERE user_email = ? AND candidate_type = 'Campus Congressperson';
    `;
    const [voteData] = await db.execute(voteQuery, [email]);

    const votedCandidateId = voteData.length > 0 ? voteData[0].candidate_id : null;

    if (congressPeople.length > 0) {
      return res.json({ congressPeople, campusName, campusId, votedCandidateId }); // Include both campus name and ID
    } else {
      console.log('No candidates found for the specified campus and role');
      return res.status(404).send('No candidates found for the specified campus and role');
    }

  } catch (err) {
    console.error('Error fetching data:', err);
    return res.status(500).send('Error fetching data');
  }
});



app.get('/api/getCongressPeopleByStudentType', async (req, res) => {
  const email = req.query.email;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`;

  if (!email) {
    console.log('Error: Email is missing');
    return res.status(400).send('Email is required');
  }

  try {
    // Step 1: Fetch user data
    const userQuery = `
      SELECT student_type
      FROM users
      WHERE email = ?;
    `;
    const [userData] = await db.execute(userQuery, [email]);

    if (userData.length === 0) {
      console.log('No user found with email:', email);
      return res.status(404).send('User not found');
    }

    let { student_type } = userData[0];

    console.log('Student type:', student_type);

    // Transform student_type if it's 'CEP'
    if (student_type === 'CEP') {
      student_type = 'CEP Congressperson';
    } else if (student_type === 'DSVOL') {
      student_type = 'DSVOL Congressperson';
    } else {
      student_type = 'Regular Congressperson';
    }

    // Step 2: Fetch congressperson_type ID from congresspersonrole table
    const roleQuery = `
      SELECT id
      FROM congresspersonroles
      WHERE congressname LIKE CONCAT('%', ?, '%');
    `;
    const [roleData] = await db.execute(roleQuery, [student_type]);

    if (roleData.length === 0) {
      console.log('No congressperson role found for student_type:', student_type);
      return res.status(404).send('No congressperson role found for the specified student type');
    }

    const { id: congresspersonTypeId } = roleData[0];

    console.log('Congressperson type ID:', congresspersonTypeId);

    // Step 3: Fetch congresspeople by congressperson_type ID
    const congressPeopleQuery = `
      SELECT *
      FROM ${schemaName}.candidates
      WHERE congressperson_type = ?;
    `;
    const [congressPeople] = await db.execute(congressPeopleQuery, [congresspersonTypeId]);

    // Step 4: Fetch the user's vote
    const voteQuery = `
      SELECT candidate_id
      FROM ${schemaName}.full_votes
      WHERE user_email = ? AND candidate_type = ?;
    `;
    const [voteData] = await db.execute(voteQuery, [email, student_type]);

    const votedCandidateId = voteData.length > 0 ? voteData[0].candidate_id : null;

    if (congressPeople.length > 0) {
      return res.json({
        congressPeople,
        studentType: student_type, // Include transformed student_type in the response
        votedCandidateId
      });
    } else {
      console.log('No congresspeople found for congressperson_type ID:', congresspersonTypeId);
      return res.status(404).send('No congresspeople found for the specified congressperson type');
    }

  } catch (err) {
    console.error('Error fetching data:', err);
    return res.status(500).send('Error fetching data');
  }
});


app.get('/api/fetchCandidatesByResidency', async (req, res) => {
  const email = req.query.email;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`;

  if (!email) {
    console.log('Error: Email is missing');
    return res.status(400).send('Email is required');
  }

  try {
    // Step 1: Fetch user data
    const userQuery = `
      SELECT residency_status, campus
      FROM users
      WHERE email = ?;
    `;
    const [userData] = await db.execute(userQuery, [email]);

    if (userData.length === 0) {
      console.log('No user found with email:', email);
      return res.status(404).send('User not found');
    }

    const { residency_status, campus } = userData[0];
    console.log('User residency status:', residency_status);
    console.log('User campus ID:', campus);

    // Check if the user is from the main campus
    if (campus !== 1) {
      console.log('User is not from the main campus');
      return res.status(403).send('Access denied. Only main campus users can view these candidates.');
    }

    // Step 2: Fetch candidates by residency for the main campus
    const candidatesQuery = `
      SELECT *
      FROM ${schemaName}.candidates
      WHERE congressperson_type = 9;
    `;
    const [Residentcandidates] = await db.execute(candidatesQuery);

    // Step 3: Fetch the user's vote
    const voteQuery = `
      SELECT candidate_id
      FROM ${schemaName}.full_votes
      WHERE user_email = ? AND candidate_type = 'Non-Resident Congressperson';
    `;
    const [voteData] = await db.execute(voteQuery, [email]);

    const votedCandidateId = voteData.length > 0 ? voteData[0].candidate_id : null;

    if (Residentcandidates.length > 0) {
      const response = {
        Residentcandidates,
        votedCandidateId
      };
      return res.json(response);
    } else {
      console.log('No candidates found for residency status:', residency_status);
      return res.status(404).send('No candidates found for the specified residency status in the main campus');
    }
  } catch (err) {
    console.error('Error fetching data:', err);
    return res.status(500).send('Error fetching data');
  }
});



app.get('/api/getCongressPeopleByDisability', async (req, res) => {
  const email = req.query.email;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`;

  if (!email) {
    console.log('Error: Email is missing');
    return res.status(400).send('Email is required');
  }

  try {
    // Step 1: Fetch user data
    const userQuery = `
      SELECT disabled
      FROM users
      WHERE email = ?;
    `;
    const [userData] = await db.execute(userQuery, [email]);

    if (userData.length === 0) {
      console.log('No user found with email:', email);
      return res.status(404).send('User not found');
    }

    const { disabled } = userData[0];

 console.log('User disabled status:', disabled);
    if (disabled !== 1) {
      console.log('User is not eligible to see Disabled candidates');
      return res.status(403).send('Access denied. Only Disabled users can view these candidates.');
    }

    // Step 2: Fetch congresspeople with ID 4 for disabled candidates
    const congressPeopleQuery = `
      SELECT *
      FROM ${schemaName}.candidates
      WHERE congressperson_type = 6;
    `;
    const [congressPeople] = await db.execute(congressPeopleQuery);

    // Step 3: Fetch the user's vote
    const voteQuery = `
      SELECT candidate_id
      FROM ${schemaName}.full_votes
      WHERE user_email = ? AND candidate_type = 'Disabled Congressperson';
    `;
    const [voteData] = await db.execute(voteQuery, [email]);

    const votedCandidateId = voteData.length > 0 ? voteData[0].candidate_id : null;

    if (congressPeople.length > 0) {
      return res.json({ congressPeople, votedCandidateId });
    } else {
      console.log('No disabled candidates found');
      return res.status(404).send('No disabled candidates found');
    }

  } catch (err) {
    console.error('Error fetching data:', err);
    return res.status(500).send('Error fetching data');
  }
});

app.get('/api/getCongressPeopleByInternational', async (req, res) => {
  const email = req.query.email;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`;

  if (!email) {
    console.log('Error: Email is missing');
    return res.status(400).send('Email is required');
  }

  try {
    // Step 1: Fetch user data
    const userQuery = `
      SELECT internationalstudent
      FROM users
      WHERE email = ?;
    `;
    const [userData] = await db.execute(userQuery, [email]);

    if (userData.length === 0) {
      console.log('No user found with email:', email);
      return res.status(404).send('User not found');
    }

    const { internationalstudent } = userData[0];

    if (internationalstudent !== 1) {
      console.log('User is not eligible to see international candidates');
      return res.status(403).send('User is not eligible to see international candidates');
    }

    console.log('Fetching international candidates for user:', email);

    // Step 2: Fetch congresspeople with ID 4 for international candidates
    const congressPeopleQuery = `
      SELECT *
      FROM ${schemaName}.candidates
      WHERE congressperson_type = 4;
    `;
    const [congressPeople] = await db.execute(congressPeopleQuery);

    // Step 3: Fetch the user's vote
    const voteQuery = `
      SELECT candidate_id
      FROM ${schemaName}.full_votes
      WHERE user_email = ? AND candidate_type = 'International Congressperson';
    `;
    const [voteData] = await db.execute(voteQuery, [email]);

    const votedCandidateId = voteData.length > 0 ? voteData[0].candidate_id : null;

    if (congressPeople.length > 0) {
      return res.json({ congressPeople, votedCandidateId });
    } else {
      console.log('No international candidates found');
      return res.status(404).send('No international candidates found');
    }

  } catch (err) {
    console.error('Error fetching data:', err);
    return res.status(500).send('Error fetching data');
  }
});










const getCandidatesBySchool = async (schoolId, userEmail, year = new Date().getFullYear()) => {
  try {
    const globalSchema = 'evoting_system'; // Replace with your global schema name
    const schemaName = `evoting_${year}`;

    // Fetch user data (including hostel) from the global schema
    const [user] = await db.execute(`
      SELECT u.hostel
      FROM ${globalSchema}.users u
      WHERE u.email = ?
    `, [userEmail]);

    const userHostel = user[0]?.hostel || null;

  console.log('User hostel:', userHostel);
    let candidatesByHostel = [];

    // Only fetch candidates by hostel if the user has a hostel associated
    if (userHostel) {
      [candidatesByHostel] = await db.execute(`
        SELECT c.id, c.name, c.admission_no, c.role, c.gender, c.motto, c.photo_path
        FROM ${schemaName}.candidates c
        WHERE c.hostel = ? 
      `, [userHostel]);
    }

    // Step 1: Fetch school population
    const [schoolData] = await db.execute(`
      SELECT population
      FROM ${globalSchema}.schools
      WHERE idschools = ?
    `, [schoolId]);

    if (schoolData.length === 0) {
      throw new Error('School not found');
    }

    const { population } = schoolData[0];

    // Step 2: Determine the number of congresspersons based on population
    let candidatesBySchool;
    if (population > 6999) {
      // Fetch one male and one female congressperson
      [candidatesBySchool] = await db.execute(`
        SELECT c.id, c.name, c.admission_no, c.role, c.gender, c.motto, c.photo_path
        FROM ${schemaName}.candidates c
        WHERE c.school_id = ? AND (c.gender = 'Male' OR c.gender = 'Female')
      `, [schoolId]);
    } else {
      // Fetch any one congressperson
      [candidatesBySchool] = await db.execute(`
        SELECT c.id, c.name, c.admission_no, c.role, c.gender, c.motto, c.photo_path
        FROM ${schemaName}.candidates c
        WHERE c.school_id = ?
      `, [schoolId]);
    }

    // Return both sets of candidates, userHostel, and year
    return {
      candidatesByHostel,
      candidatesBySchool,
      userHostel,
      year,
      population // Include population for informational purposes
    };

  } catch (error) {
    console.error('Error fetching candidates:', error);
    throw error; // Re-throw error to be caught by the route handler
  }
};




app.get('/candidates', async (req, res) => {
  const { schoolId, email } = req.query;

  // Check if schoolId and email are provided
  if (!schoolId || !email) {
    return res.status(400).json({ error: 'Missing schoolId or email parameter' });
  }

  try {
    const { candidatesBySchool, candidatesByHostel, population } = await getCandidatesBySchool(schoolId, email);

    if (candidatesBySchool.length === 0) {
      return res.json({ message: "No candidates available for your school." });
    }

    res.json({ candidatesBySchool, candidatesByHostel, population });
  } catch (error) {
    console.error('Error fetching candidates:', error);
    res.status(500).json({ error: 'Failed to fetch candidates' });
  }
});




app.get('/api/candidates', async (req, res) => {
  const { status } = req.query;
  let isApproved;
  if (status === 'approved') {
    isApproved = 1;
  } else if (status === 'declined') {
    isApproved = -1;
  } else {
    isApproved = 0;
  }

  try {
    const [candidates] = await db.query(
      `SELECT c.id, c.name, d.department_name, c.role, c.is_approved
       FROM candidates c
       JOIN departments d ON c.department_id = d.id
       WHERE c.is_approved = ?`, [isApproved]
    );
    res.json(candidates);
  } catch (error) {
    console.error('Error fetching candidates:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/candidates/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [candidate] = await db.query('SELECT * FROM candidates WHERE id = ?', [id]);
    if (candidate.length === 0) {
      return res.status(404).json({ message: 'Candidate not found' });
    }

  
    
    res.json({ candidate: candidate[0]});
  } catch (error) {
    console.error('Error fetching candidate details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/candidates/school/:schoolId', async (req, res) => {
  const { schoolId } = req.params;
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name

  try {
    // Query to fetch candidates by school from the dynamic schema
    const [candidates] = await db.query(
      `
      SELECT id, name,admission_no,role,gender,motto, photo_path AS photo
      FROM ${schemaName}.candidates
      WHERE school_id = ?
      `,
      [schoolId]
    );

    if (candidates.length === 0) {
      return res.status(404).json({ message: "No candidates available for this school." });
    }

    res.json({ candidates });
  } catch (error) {
    console.error('Error fetching candidates by school:', error);
    res.status(500).json({ error: 'Failed to fetch candidates' });
  }
});

app.get('/api/candidates/congress/:congressId', async (req, res) => {
  const { congressId } = req.params;
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name

  try {
    // Query to fetch candidates by school from the dynamic schema
    const [candidates] = await db.query(
      `
      SELECT id, name,admission_no,role,gender,motto, photo_path AS photo
      FROM ${schemaName}.candidates
      WHERE congressperson_type = ?
      `,
      [congressId]
    );

    if (candidates.length === 0) {
      return res.status(404).json({ message: "No candidates available for this school." });
    }

    res.json({ candidates });
  } catch (error) {
    console.error('Error fetching candidates by school:', error);
    res.status(500).json({ error: 'Failed to fetch candidates' });
  }
});



app.post('/vote', async (req, res) => {
  const { userId, candidateId } = req.body;

  try {
      // Check if the user has already voted
      const [existingVote] = await db.execute('SELECT * FROM votes WHERE user_id = ?', [userId]);
      if (existingVote.length > 0) {
          return res.status(400).json({ message: 'User has already voted' });
      }

      // Insert the new vote
      await db.execute('INSERT INTO votes (user_id, candidate_id) VALUES (?, ?)', [userId, candidateId]);
      return res.status(201).json({ message: 'Vote cast successfully' });
  } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'Server error' });
  }
});

app.get('/leaders', async (req, res) => {
  const { school } = req.query; 
  try {
    const leaders = await getLeadersBySchool(school);
    res.json({ leaders });
  } catch (error) {
    console.error('Error fetching leaders:', error);
    res.status(500).json({ error: 'Failed to fetch leaders' });
  }
});



app.get('/vote-details/:voteId', async (req, res) => {
  const { voteId } = req.params;

  try {
    const [voteDetails] = await db.query(
      'SELECT * FROM votes WHERE vote_id = ?',
      [voteId]
    );

    if (voteDetails.length > 0) {
      // You can return additional information such as leader names, etc.
      res.json(voteDetails[0]);
    } else {
      res.status(404).json({ message: 'Vote details not found' });
    }
  } catch (err) {
    console.error('Error fetching vote details:', err);
    res.status(500).json({ message: 'Failed to fetch vote details' });
  }
});


app.post('/vote', async (req, res) => {
  const { email, leaderId, role } = req.body;

  try {
    // Check if the user has already voted
    const existingVote = await db.query('SELECT * FROM votes WHERE voter_email = ? AND candidate_id = ?', [email, leaderId]);
    if (existingVote.length > 0) {
      return res.status(400).json({ success: false, message: 'You have already voted for this candidate.' });
    }

    // Insert the vote
    await db.query('INSERT INTO votes (candidate_id, voter_email, role) VALUES (?, ?, ?)', [leaderId, email, role]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error casting vote:', error);
    res.status(500).json({ success: false, message: 'Error casting vote.' });
  }
});

app.get('/votes/tally', async (req, res) => {
  try {
    const tally = {
      hostelReps: [],
      delegates: [],
      congressPersons: []
    };

    // Tally votes for Hostel Reps
    const hostelReps = await db.query('SELECT candidate_id, COUNT(*) AS votes FROM votes WHERE role = "Hostel Rep" GROUP BY candidate_id');
    tally.hostelReps = hostelReps;

    // Tally votes for Delegates
    const delegates = await db.query('SELECT candidate_id, COUNT(*) AS votes FROM votes WHERE role = "Delegate" GROUP BY candidate_id');
    tally.delegates = delegates;

    // Tally votes for Congress Persons
    const congressPersons = await db.query('SELECT candidate_id, COUNT(*) AS votes FROM votes WHERE role = "Congress Person" GROUP BY candidate_id');
    tally.congressPersons = congressPersons;

    res.json(tally);
  } catch (error) {
    console.error('Error fetching vote tally:', error);
    res.status(500).json({ message: 'Error fetching vote tally.' });
  }
});






app.post('/vote/delegate', async (req, res) => {
  const { email, leaderId, schoolId, year = new Date().getFullYear() } = req.body;

  try {
    if (!email || !leaderId || !schoolId) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const schemaName = `evoting_${String(year).replace(/[^0-9]/g, "")}`;

    // Check if the user has already voted
    const [existingVote] = await db.query(
      `SELECT email FROM ??.delegates_votes WHERE email = ? LIMIT 1`,
      [schemaName, email]
    );

    if (existingVote.length > 0) {
      return res.status(400).json({ message: "You have already voted." });
    }

    // Insert vote with email
    await db.query(
      `INSERT INTO ??.delegates_votes (leader_id, school_id, email, vote_count) 
       VALUES (?, ?, ?, 1)`,
      [schemaName, leaderId, schoolId, email]
    );

    res.json({ success: true, message: "Vote cast successfully!" });
  } catch (err) {
    console.error("Error casting vote:", err); // Log error
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
});

app.post('/vote/congressperson', async (req, res) => {
  const { email, leaderId, schoolId, year = new Date().getFullYear() } = req.body;

  try {
    if (!email || !leaderId || !schoolId) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const schemaName = `evoting_${String(year).replace(/[^0-9]/g, "")}`;

    // Check if the user has already voted
    const [existingVote] = await db.query(
      `SELECT email FROM ??.congressperson_votes WHERE email = ? LIMIT 1`,
      [schemaName, email]
    );

    if (existingVote.length > 0) {
      return res.status(400).json({ message: "You have already voted." });
    }

    // Insert vote with email
    await db.query(
      `INSERT INTO ??.congressperson_votes (leader_id, school_id, email, vote_count) 
       VALUES (?, ?, ?, 1)`,
      [schemaName, leaderId, schoolId, email]
    );

    res.json({ success: true, message: "Vote cast successfully!" });
  } catch (err) {
    console.error("Error casting vote:", err); // Log error
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
});





app.post('/vote/hostelrep', async (req, res) => {
  const { email, leaderId, schoolId, year = new Date().getFullYear() } = req.body;

  try {
    if (!email || !leaderId || !schoolId) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const schemaName = `evoting_${String(year).replace(/[^0-9]/g, "")}`;

    // Check if the user has already voted
    const [existingVote] = await db.query(
      `SELECT email FROM ??.hostelrep_votes WHERE email = ? LIMIT 1`,
      [schemaName, email]
    );

    if (existingVote.length > 0) {
      return res.status(400).json({ message: "You have already voted." });
    }

    // Insert vote with email
    await db.query(
      `INSERT INTO ??.hostelrep_votes (leader_id, school_id, email, vote_count) 
       VALUES (?, ?, ?, 1)`,
      [schemaName, leaderId, schoolId, email]
    );

    res.json({ success: true, message: "Vote cast successfully!" });
  } catch (err) {
    console.error("Error casting vote:", err); // Log error
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
});





app.get('/api/admin/vote-stats', async (req, res) => {
  try {
    const congresspersonVotes = `
      SELECT c.name AS candidateName,c.photo_path AS photo , cv.leader_id, SUM(cv.vote_count) AS voteCount
      FROM congressperson_votes AS cv
      JOIN candidates AS c ON cv.leader_id = c.id  -- Use c.id instead of c.leader_id
      GROUP BY cv.leader_id, c.name
    `;
    
    const delegateVotes = `
      SELECT c.name AS candidateName,c.photo_path AS photo , dv.leader_id, SUM(dv.vote_count) AS voteCount
      FROM delegates_votes AS dv
      JOIN candidates AS c ON dv.leader_id = c.id  -- Use c.id instead of c.leader_id
      GROUP BY dv.leader_id, c.name
    `;
    
    const hostelRepVotes = `
      SELECT c.name AS candidateName,c.photo_path AS photo , hrv.leader_id, SUM(hrv.vote_count) AS voteCount
      FROM hostelrep_votes AS hrv
      JOIN candidates AS c ON hrv.leader_id = c.id  -- Use c.id instead of c.leader_id
      GROUP BY hrv.leader_id, c.name
    `;

    // Execute the queries and get the rows
    const [congressResults] = await db.query(congresspersonVotes);
    const [delegateResults] = await db.query(delegateVotes);
    const [hostelRepResults] = await db.query(hostelRepVotes);

    // Check if results are returned as expected, adjust if necessary
    const voteStats = {
      congressperson: congressResults || [],
      delegate: delegateResults || [],
      hostelRep: hostelRepResults || [],
    };

    res.json(voteStats);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch vote stats' });
  }
});
app.get('/api/admin/vote-stats/:type/:id', async (req, res) => {
  const { type, id } = req.params;
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name

  const voteQueries = {
    school: {
      congressperson: `
       SELECT c.name AS candidateName, 
       c.photo_path AS photo, 
       vs.leader_id, 
       SUM(vs.total_votes) AS voteCount
FROM ${schemaName}.congressperson_results AS vs
JOIN ${schemaName}.candidates AS c ON vs.leader_id = c.id
JOIN congresspersonroles AS cr ON c.congressperson_type = cr.id
WHERE c.school_id = ? AND cr.id = 1
GROUP BY vs.leader_id, c.name, c.photo_path;

      `,
      delegate: `
        SELECT c.name AS candidateName, c.photo_path AS photo, dv.leader_id, SUM(dv.vote_count) AS voteCount
        FROM ${schemaName}.delegates_votes AS dv
        JOIN ${schemaName}.candidates AS c ON dv.leader_id = c.id
        WHERE c.school_id = ?
        GROUP BY dv.leader_id, c.name, c.photo_path
      `,
      hostelRep: `
        SELECT c.name AS candidateName, c.photo_path AS photo, hrv.leader_id, SUM(hrv.vote_count) AS voteCount
        FROM ${schemaName}.hostelrep_votes AS hrv
        JOIN ${schemaName}.candidates AS c ON hrv.leader_id = c.id
        WHERE c.school_id = ?
        GROUP BY hrv.leader_id, c.name, c.photo_path
      `,
    },
    house: {
      candidates: `
        SELECT c.name AS candidateName, c.photo_path AS photo, hrv.leader_id, SUM(hrv.vote_count) AS voteCount
        FROM ${schemaName}.hostelrep_votes AS hrv
        JOIN ${schemaName}.candidates AS c ON hrv.leader_id = c.id
        WHERE c.school_id = ?
        GROUP BY hrv.leader_id, c.name, c.photo_path
      `,
    },
  };

  try {
    const queries = voteQueries[type];
    if (!queries) {
      return res.status(400).json({ error: 'Invalid type specified' });
    }

    const results = await Promise.all(
      Object.entries(queries).map(async ([key, query]) => {
        const [rows] = await db.query(query, [id]);
        return { [key]: rows };
      })
    );

    const data = results.reduce((acc, curr) => ({ ...acc, ...curr }), {});
    res.json(data);
  } catch (err) {
    console.error('Error fetching vote stats:', err);
    res.status(500).json({ error: 'Failed to fetch vote stats' });
  }
});





app.get('/api/candidates/house/:houseId', async (req, res) => {
  const { houseId } = req.params;

  try {
    const candidatesQuery = `
      SELECT c.name AS candidateName, c.photo_path AS photo, dv.leader_id, SUM(dv.vote_count) AS voteCount
      FROM hostelrep_votes AS dv
      JOIN candidates AS c ON dv.leader_id = c.id
      WHERE c.hostel = ?
      GROUP BY dv.leader_id, c.name, c.photo_path
    `;
    
    const [candidatesResults] = await db.query(candidatesQuery, [houseId]);

    res.json({ candidates: candidatesResults });
  } catch (error) {
    console.error('Error fetching candidates for house:', error);
    res.status(500).json({ error: 'Failed to fetch candidates for house' });
  }
});



app.get('/api/elections', async (req, res) => {
  try {
    // Await the query result instead of using a callback
    const [rows] = await db.query('SELECT * FROM elections');
    res.status(200).json(rows); // Send the rows to the client
  } catch (error) {
    console.error('Error fetching elections:', error);  // Log the full error details
    res.status(500).json({ error: 'Failed to fetch elections' });
  }
});


// Example: Create an election
const formatDateForMySQL = (date) => {
  if (!date) {
    throw new Error("Invalid date");
  }
  return new Date(date).toISOString().slice(0, 19).replace("T", " ");
};



app.post('/api/elections', async (req, res) => {
  const { name, start_date, end_date, year } = req.body;

  if (!name || !start_date || !end_date || !year) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Start a transaction
    await db.query('START TRANSACTION');

    // Insert the new election
    const formattedStartDate = new Date(start_date).toISOString().slice(0, 19).replace('T', ' ');
    const formattedEndDate = new Date(end_date).toISOString().slice(0, 19).replace('T', ' ');

    const [result] = await db.query(
      `INSERT INTO elections (name, start_date, end_date, year) VALUES (?, ?, ?, ?)`,
      [name, formattedStartDate, formattedEndDate, year]
    );

    // Call the stored procedure to create the schema and tables
    await db.query(`CALL CreateNewSchemaWithTables2024(?)`, [year]);

    // Commit the transaction
    await db.query('COMMIT');

    res.status(201).json({ message: "Election created successfully", id: result.insertId });
  } catch (error) {
    console.error("Error creating election:", error);

    // Rollback the transaction in case of an error
    await db.query('ROLLBACK');

    res.status(500).json({ error: "Error creating election" });
  }
});




app.get("/api/elections", async (req, res) => {
  const { year } = req.query;

  try {
    const query = year
      ? `SELECT * FROM elections WHERE year = ?`
      : `SELECT * FROM elections`;

    const [rows] = await db.query(query, year ? [year] : []);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching elections:", error);
    res.status(500).json({ error: "Error fetching elections" });
  }
});

// Update election dates
app.put("/api/elections/:id/dates", async (req, res) => {
  const { id } = req.params;
  const { start_date, end_date } = req.body;

  if (!start_date || !end_date) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const formattedStartDate = formatDateForMySQL(start_date);
    const formattedEndDate = formatDateForMySQL(end_date);

    await db.query(
      `UPDATE elections SET start_date = ?, end_date = ? WHERE id = ?`,
      [formattedStartDate, formattedEndDate, id]
    );

    res.json({ message: "Election dates updated" });
  } catch (error) {
    console.error("Error updating election dates:", error);
    res.status(500).json({ error: "Error updating election dates" });
  }
});






















//////////////////////////////////////////////////////////////////////////////////////////


// Update election status
app.put('/api/elections/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // 'open' or 'closed'

  if (!['open', 'closed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  try {
    await db.query('UPDATE elections SET status = ? WHERE id = ?', [status, id]);
    res.status(200).json({ message: 'Election status updated successfully' });
  } catch (error) {
    console.error('Error updating election status:', error);
    res.status(500).json({ error: 'Failed to update election status' });
  }
});

// Update election dates
app.put('/api/elections/:id/dates', async (req, res) => {
  const { start_date, end_date } = req.body;
  const electionId = req.params.id;

  // Function to format date to MySQL datetime format
  const formatDateForMySQL = (date) => {
    if (!date) {
      throw new Error('Invalid date');
    }
    return new Date(date).toISOString().slice(0, 19).replace('T', ' ');
  };

  try {
    console.log('Received start_date:', start_date);
    console.log('Received end_date:', end_date);

    const formattedStartDate = formatDateForMySQL(start_date);
    const formattedEndDate = formatDateForMySQL(end_date);

    console.log('Formatted start_date:', formattedStartDate);
    console.log('Formatted end_date:', formattedEndDate);

    await db.query(
      'UPDATE elections SET start_date = ?, end_date = ? WHERE id = ?',
      [formattedStartDate, formattedEndDate, electionId]
    );
    res.status(200).json({ message: 'Dates updated successfully' });
  } catch (error) {
    console.error('Error updating dates:', error);
    res.status(500).json({ error: 'Failed to update dates' });
  }
});



app.get('/api/elections/:id/status', async (req, res) => {
  const { id } = req.params;

  try {
    console.log(`Checking status for election ID: ${id}`);
    const [rows] = await db.query('SELECT end_date FROM elections WHERE id = ?', [id]);
    if (rows.length === 0) {
      console.log(`Election not found for ID: ${id}`);
      return res.status(404).json({ error: 'Election not found' });
    }

    const endDate = new Date(rows[0].end_date);
    const currentDate = new Date();

   

    if (currentDate > endDate) {
      
      return res.status(200).json({ status: 'closed' });
    } else {
      console.log(`Election ID: ${id} is open`);
      return res.status(200).json({ status: 'open' });
    }
  } catch (error) {
    console.error('Error checking election status:', error);
    res.status(500).json({ error: 'Failed to check election status' });
  }
});

app.post('/admin/register', async (req, res) => {
  const { email, password, name } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)', [email, hashedPassword, name, 'admin']);
    res.status(201).json({ success: true, id: result.insertId });
  } catch (error) {
    console.error('Error registering admin:', error);
    res.status(500).json({ success: false, error: 'Failed to register admin' });
  }
});

app.post('/vote', async (req, res) => {
  const { email, leaderId, role, schoolId } = req.body;

  try {
    // Check if user already voted for the role
    const existingVote = await db.query(
      'SELECT * FROM votes WHERE email = ? AND role = ?',
      [email, role]
    );

    if (existingVote.length > 0) {
      return res.status(400).json({ success: false, message: 'You have already voted for this role!' });
    }

    // Record the vote
    await db.query(
      'INSERT INTO votes (email, leader_id, role, school_id, created_at) VALUES (?, ?, ?, ?, NOW())',
      [email, leaderId, role, schoolId]
    );

    return res.json({ success: true, message: 'Vote cast successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error processing vote.' });
  }
});

app.get('/voting-status', async (req, res) => {
  const { email } = req.query;

  try {
    const votes = await db.query('SELECT role FROM votes WHERE email = ?', [email]);
    res.json({ success: true, votes });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error fetching voting status.' });
  }
});

app.post('/saveVote', async (req, res) => {
  const { email, leaderId, role } = req.body;

  // Validate required parameters
  if (!email || !leaderId || !role) {
    return res.status(400).json({ message: 'Missing required parameters' });
  }

  try {
    // Step 1: Check if the user has already voted for this category
    const [existingVote] = await db.query('SELECT * FROM votes WHERE email = ? AND role = ?', [email, role]);

    if (existingVote.length > 0) {
      // If the user has already voted for this category, reject the new vote
      return res.status(400).json({ message: 'You have already voted for this category.' });
    }

    // Step 2: Insert the new vote into the database
    const query = `
      INSERT INTO votes (email, leader_id, role) 
      VALUES (?, ?, ?)
    `;
    const values = [email, leaderId, role];

    await db.query(query, values);

    // Step 3: Respond with success
    return res.status(200).json({ success: true, message: 'Vote saved successfully' });
  } catch (error) {
    console.error('Error saving vote:', error);
    return res.status(500).json({ message: 'Error saving vote' });
  }
});

///////////////////President///////////////////////////////////////////////////////////////

// Get all leaders
app.get('/leaders', async (req, res) => {
  try {
    const [leaders] = await db.query('SELECT * FROM leaders');
    res.json({ success: true, leaders });
  } catch (error) {
    console.error('Error fetching leaders:', error);
    res.status(500).json({ success: false, message: 'Error fetching leaders' });
  }
});

// Get a specific leader by ID
app.get('/leaders/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [leader] = await db.query('SELECT * FROM leaders WHERE id = ?', [id]);
    if (leader.length === 0) {
      return res.status(404).json({ success: false, message: 'Leader not found' });
    }
    res.json({ success: true, leader: leader[0] });
  } catch (error) {
    console.error('Error fetching leader:', error);
    res.status(500).json({ success: false, message: 'Error fetching leader' });
  }
});

// Create a new leader
app.post('/leaders', async (req, res) => {
  const { partyId, position, name } = req.body;

  // Validate required parameters
  if (!partyId || !position || !name) {
    return res.status(400).json({ message: 'Missing required parameters' });
  }

  try {
    const query = 'INSERT INTO leaders (party_id, position, name) VALUES (?, ?, ?)';
    const values = [partyId, position, name];

    await db.query(query, values);

    res.status(201).json({ success: true, message: 'Leader created successfully' });
  } catch (error) {
    console.error('Error creating leader:', error);
    res.status(500).json({ success: false, message: 'Error creating leader' });
  }
});

// Update a leader
app.put('/leaders/:id', async (req, res) => {
  const { id } = req.params;
  const { partyId, position, name } = req.body;

  // Validate required parameters
  if (!partyId || !position || !name) {
    return res.status(400).json({ message: 'Missing required parameters' });
  }

  try {
    const query = 'UPDATE leaders SET party_id = ?, position = ?, name = ? WHERE id = ?';
    const values = [partyId, position, name, id];

    const [result] = await db.query(query, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Leader not found' });
    }

    res.json({ success: true, message: 'Leader updated successfully' });
  } catch (error) {
    console.error('Error updating leader:', error);
    res.status(500).json({ success: false, message: 'Error updating leader' });
  }
});

// Delete a leader
app.delete('/leaders/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.query('DELETE FROM leaders WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Leader not found' });
    }

    res.json({ success: true, message: 'Leader deleted successfully' });
  } catch (error) {
    console.error('Error deleting leader:', error);
    res.status(500).json({ success: false, message: 'Error deleting leader' });
  }
});




app.post('/api/register-president', upload.array('images'), async (req, res) => {
  const { partyName, motto, campaignObjectives, leaders, email, password } = req.body;
  const files = req.files;
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name


  // Assuming the first file is the party banner image and the rest are leaders' images
  const partyBannerFile = files[0];  // First file is the party banner
  const leaderFiles = files.slice(1); // The remaining files are the leaders' images

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user details into the database
    const [userResult] = await db.query(
      'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
      [email, hashedPassword, 'president']
    );

    const presidentId = userResult.insertId;

    // Insert party details into the database
    const bannerImagePath = partyBannerFile ? partyBannerFile.path : null;  // Get the banner image path
    const [partyResult] = await db.query(
      `INSERT INTO ${schemaName}.parties (party_name, motto, campaign_objectives, president_id, banner_image) VALUES (?, ?, ?, ?, ?)`,
      [partyName, motto, campaignObjectives, presidentId, bannerImagePath]
    );

    const partyId = partyResult.insertId;

    // Insert leaders into the database
    for (let i = 0; i < leaders.length; i++) {
      const leader = leaders[i];
      const leaderImage = leaderFiles[i] ? leaderFiles[i].path : null;  // Get the leader image path
      await db.query(
        `INSERT INTO ${schemaName}.leaders (party_id, position, name, image) VALUES (?, ?, ?, ?)`,
        [partyId, leader.position, leader.name, leaderImage]
      );
    }

    res.status(201).json({ success: true, message: 'President registered successfully' });
  } catch (error) {
    console.error('Error registering president:', error);
    res.status(500).json({ success: false, message: 'Failed to register president' });
  }
});




app.get('/api/party', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name


  if (!token) {
    return res.status(401).json({ message: 'Authorization token is required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const presidentId = decoded.userId;


    const [partyDetails] = await db.query(
      `SELECT * FROM ${schemaName}.parties WHERE president_id = ?`,
      [presidentId]
    );

    if (partyDetails.length === 0) {
      return res.status(404).json({ message: 'Party not found' });
    }

    const [leaders] = await db.query(
      `SELECT * FROM ${schemaName}.leaders WHERE party_id = ?`,
      [partyDetails[0].id]
    );

 

    res.json({ ...partyDetails[0], leaders });
  } catch (error) {
    console.error('Error fetching party details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/president-stats-votes', async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT party_id, COUNT(*) as vote_count 
      FROM presidential_votes 
      GROUP BY party_id
    `);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching votes' });
  }
});

app.get('/candidate-status', async (req, res) => {
  const { email } = req.query;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name


  console.log('Checking candidate status for:', email);
  try {
    // Fetch the user's admission number based on their email
    const [userDetails] = await db.query(
      'SELECT admissionno FROM users WHERE email = ?',
      [email]
    );


    if (userDetails.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const admissionNo = userDetails[0].admissionno; // Corrected field name
 
    console.log('Admission number:', admissionNo);
    // Check if the admission number exists in the candidates table
    const [candidateDetails] = await db.query(
      `SELECT * FROM ${schemaName}.candidates WHERE admission_no = ?`,
      [admissionNo]
    );
 
    if (candidateDetails.length === 0) {
      return res.json({ isCandidate: false });
    }

    res.json({ isCandidate: true });
  } catch (error) {
    console.error('Error checking candidate status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/candidate/:id', async (req, res) => {
  const { id } = req.params;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name

  try {
    // Fetch the user's admission number using the provided user id
    const [userDetails] = await db.query(
      'SELECT admissionno FROM users WHERE id = ?',
      [id]
    );

    if (userDetails.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const { admissionno } = userDetails[0]; 
    const [candidateDetails] = await db.query(
      `SELECT * FROM ${schemaName}.candidates WHERE admission_no = ?`,
      [admissionno]
    );
    

    if (candidateDetails.length === 0) {
      return res.status(404).json({ message: 'Candidate not found' });
    }

    const candidate = candidateDetails[0];


    let performanceData = [];
    let otherCandidatesData = [];
    let hasWon = false;

    // Fetch performance data based on the candidate's role
    if (candidate.role === '2') {
      [performanceData] = await db.query(
        'SELECT * FROM hostelrep_votes WHERE leader_id = ?',
        [candidate.id]
      );
    } else if (candidate.role === '3') {
      [performanceData] = await db.query(
        'SELECT * FROM delegates_votes WHERE leader_id = ?',
        [candidate.id]
      );
      [otherCandidatesData] = await db.query(
        'SELECT c.name, dv.vote_count FROM candidates c JOIN delegates_votes dv ON c.id = dv.leader_id WHERE c.school_id = ? AND c.id != ?',
        [candidate.school_id, candidate.id]
      );
      
    }else if (candidate.congressperson_type) {
      [performanceData] = await db.query(
        `SELECT * FROM  ${schemaName}.full_votes WHERE candidate_id = ?`,
        [candidate.id]
      );
      [otherCandidatesData] = await db.query(
        `SELECT c.name, COUNT(dv.candidate_id) AS vote_count
FROM candidates c
JOIN evoting_2025.full_votes dv
ON c.id = dv.candidate_id
WHERE c.school_id = ? AND c.id != ?
GROUP BY c.id
`,
        [candidate.school_id, candidate.id]
      );
      
    }
     else if (candidate.role === '1') {
      [performanceData] = await db.query(
        `SELECT * FROM ${schemaName}.congressperson_results WHERE leader_id = ?`,
        [candidate.id]
      );
      [otherCandidatesData] = await db.query(
        `SELECT c.name, cv.total_votes FROM candidates c JOIN ${schemaName}.congressperson_results cv ON c.id = cv.leader_id WHERE c.school_id = ? AND c.id != ?`,
        [candidate.school_id, candidate.id]
      );
    }

    // Determine if the candidate has won in their school
    const totalVotes = performanceData.reduce((acc, data) => acc + data.total_votes, 0);
    const maxVotes = Math.max(...performanceData.map(data => data.total_votes));
    if (totalVotes === maxVotes) {
      hasWon = true;
    }

    res.json({ ...candidate, performanceData, otherCandidatesData, hasWon });
  } catch (error) {
    console.error('Error fetching candidate details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


app.get('/api/winners', async (req, res) => {

  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name

  try {
    // Fetch the winners for each category grouped by school
    const [houseRepWinners] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, c.hostel, hr.vote_count, c.photo_path
       FROM ${schemaName}.candidates c
       JOIN ${schemaName}.hostelrep_votes hr ON c.id = hr.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE hr.vote_count = (
         SELECT MAX(hr2.vote_count)
         FROM ${schemaName}.hostelrep_votes hr2
         JOIN ${schemaName}.candidates c2 ON hr2.leader_id = c2.id
         WHERE c2.school_id = c.school_id
       )`
    );

    const [delegateWinners] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, d.vote_count, c.photo_path
       FROM ${schemaName}.candidates c
       JOIN ${schemaName}.delegates_votes d ON c.id = d.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE d.vote_count = (
         SELECT MAX(d2.vote_count)
         FROM ${schemaName}.delegates_votes d2
         JOIN ${schemaName}.candidates c2 ON d2.leader_id = c2.id
         WHERE c2.school_id = c.school_id
       )`
    );

    const [congresspersonWinners] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, cp.vote_count, c.photo_path
       FROM ${schemaName}.candidates c
       JOIN ${schemaName}.congressperson_votes cp ON c.id = cp.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE cp.vote_count = (
         SELECT MAX(cp2.vote_count)
         FROM ${schemaName}.congressperson_votes cp2
         JOIN ${schemaName}.candidates c2 ON cp2.leader_id = c2.id
         WHERE c2.school_id = c.school_id
       )`
    );

    res.json({
      houseRepWinners,
      delegateWinners,
      congresspersonWinners,
    });
  } catch (error) {
    console.error('Error fetching winners:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/all/presidential-candidates', async (req, res) => {
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name

  try {
    const [presidentialCandidates] = await db.query(
      `SELECT p.id, p.party_name, p.motto, p.campaign_objectives, l.name AS president_name, s.name AS secretary_name
       FROM ${schemaName}.parties p
       JOIN  ${schemaName}.leaders l ON p.id = l.party_id AND l.position = 'Secretary'
       LEFT JOIN  ${schemaName}.leaders s ON p.id = s.party_id AND s.position = 'Vice President'`
    );
    res.json(presidentialCandidates);
  } catch (error) {
    console.error('Error fetching presidential candidates:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/vote-president', async (req, res) => {
  const { email, partyId } = req.body;
  const year = req.query.year || new Date().getFullYear(); // Extract year or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name
  const secretKey = process.env.SECRET_KEY || 'your-secret-key'; // Replace with a secure key from your environment

  if (!email || !partyId) {
    return res.status(400).json({ message: 'Email and partyId are required.' });
  }

  try {
    // Generate anonymous ID
    const anonymousId = crypto.createHmac('sha256', secretKey)
                              .update(email)
                              .digest('hex');

    // Check if this anonymous ID has already voted
    const [existingVote] = await db.query(
      `SELECT * FROM ${schemaName}.presidential_votes WHERE anonymous_id = ?`,
      [anonymousId]
    );

    if (existingVote.length > 0) {
      return res.status(400).json({ message: 'You have already voted.' });
    }

    // Record the vote
    await db.query(
      `INSERT INTO ${schemaName}.presidential_votes (party_id, anonymous_id) VALUES (?, ?)`,
      [partyId, anonymousId]
    );

    res.status(200).json({ message: 'Your vote has been recorded successfully.' });
  } catch (error) {
    console.error('Error processing vote:', error);
    res.status(500).json({ message: 'An error occurred while processing your vote.' });
  }
});


app.post('/api/verify-vote', async (req, res) => {
  const { email } = req.body;
  const year = new Date().getFullYear(); // Default to current year
  const schemaName = `evoting_${year}`; // Dynamic schema name
  const secretKey = process.env.SECRET_KEY || 'your-secret-key'; // Replace with a secure key from your environment

  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  try {
    // Generate anonymous ID from email
    const anonymousId = crypto.createHmac('sha256', secretKey)
                              .update(email)
                              .digest('hex');

    // Check if the user has voted
    const [voteDetails] = await db.query(
      `SELECT * FROM ${schemaName}.presidential_votes WHERE anonymous_id = ?`,
      [anonymousId]
    );

    if (!voteDetails.length) {
      return res.status(404).json({ message: 'Vote not found.' });
    }

    res.status(200).json({ voteDetails: voteDetails[0] });
  } catch (error) {
    console.error('Error verifying vote:', error);
    res.status(500).json({ message: 'An error occurred while verifying your vote.' });
  }
});


// Route to look up a voter by anonymous number (token or identifier)
app.get('/api/admin/voter-lookup', async (req, res) => {
  const { anonymousNumber } = req.query; // Get the anonymous number from query
  const year = req.query.year || new Date().getFullYear(); // Extract year or use current year
  const schemaName = `evoting_${year}`;
  if (!anonymousNumber) {
    return res.status(400).json({ message: 'Anonymous number is required.' });
  }

  try {
    // Query to get the user's email and the candidate they voted for
    const [voterDetails] = await db.query(
      `SELECT u.email, p.party_name, l.name AS president_name
       FROM ${schemaName}.presidential_votes v
       JOIN users u ON v.id = u.id
       JOIN parties p ON v.party_id = p.id
       JOIN leaders l ON p.id = l.party_id AND l.position = 'President'
       WHERE v.anonymous_id = ?`,  // Changed to 'anonymous_id'
      [anonymousNumber]
    );

    if (voterDetails.length === 0) {
      return res.status(404).json({ message: 'No matching voter found for the given anonymous number.' });
    }

    res.status(200).json(voterDetails[0]); // Returning the first matched result
  } catch (error) {
    console.error('Error looking up voter:', error);
    res.status(500).json({ message: 'An error occurred while looking up the voter.' });
  }
});


















app.post('/api/admin/lookup-voter', async (req, res) => {
  const { anonymousId } = req.body;

  try {
    const [rows] = await db.query(
      `SELECT u.email, u.name, p.party_id, p.anonymous_id
       FROM presidential_votes p
       JOIN users u ON u.id = p.user_id
       WHERE p.anonymous_id = ?`, [anonymousId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Vote not found or anonymous ID is invalid.' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching voter details.' });
  }
});


app.get('/api/presidential-standings', async (req, res) => {
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name

  try {
    // Query to fetch presidential standings from the dynamic schema
    const [standings] = await db.query(
      `
      SELECT 
        p.id AS party_id, 
        p.party_name, 
        COALESCE(COUNT(v.id), 0) AS votes
      FROM ${schemaName}.parties p
      LEFT JOIN ${schemaName}.presidential_votes v 
        ON p.id = v.party_id
      GROUP BY p.id, p.party_name
      ORDER BY votes DESC
      `
    );

    if (standings.length === 0) {
      return res.status(404).json({ message: `No presidential standings found for the year ${year}.` });
    }

    res.json({ year, standings });
  } catch (error) {
    console.error('Error fetching presidential standings:', error);

    // Check for errors related to missing schema
    if (error.code === 'ER_NO_SUCH_TABLE') {
      return res.status(400).json({
        error: `No data available for the year ${year}. Please check the provided year or ensure the schema exists.`,
      });
    }

    res.status(500).json({ error: 'Failed to fetch presidential standings' });
  }
});


app.get('/api/president/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [candidateDetails] = await db.query(
      `SELECT p.party_name, p.motto, p.campaign_objectives, l.position, l.name, l.image
       FROM parties p
       JOIN leaders l ON p.id = l.party_id
       WHERE p.id = ?`,
      [id]
    );

    if (candidateDetails.length === 0) {
      return res.status(404).json({ message: 'Candidate not found' });
    }

    res.status(200).json(candidateDetails);
  } catch (error) {
    console.error('Error fetching candidate details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/adminwinners', async (req, res) => {
  try {
    const [winners] = await db.query(
      `SELECT c.id, c.name, c.category, c.votes 
       FROM candidates c 
       WHERE c.is_winner = TRUE`
    );
    res.status(200).json(winners);
  } catch (error) {
    console.error('Error fetching winners:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/////////////////////////////Announcements//////////////////////////////////////////////////////////
app.get('/api/announcements', async (req, res) => {
  try {
    const [announcements] = await db.query('SELECT * FROM announcements ORDER BY scheduled_date DESC');
    res.json(announcements);
  } catch (error) {
    console.error('Error fetching announcements:', error);
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});
app.post('/api/announcements', upload.single('image'), async (req, res) => {
  const { title, content, scheduled_date } = req.body;
  const imagePath = req.file ? req.file.path : null;
  try {
    const formattedDate = new Date(scheduled_date).toISOString().slice(0, 19).replace('T', ' ');
    await db.query('INSERT INTO announcements (title, content, scheduled_date, image_path) VALUES (?, ?, ?, ?)', [title, content, formattedDate, imagePath]);
    res.status(201).json({ message: 'Announcement added successfully' });
  } catch (error) {
    console.error('Error adding announcement:', error);
    res.status(500).json({ error: 'Failed to add announcement' });
  }
});

// Edit an announcement with an image
app.put('/api/announcements/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { title, content, scheduled_date } = req.body;
  const imagePath = req.file ? req.file.path : null;
  try {
    const formattedDate = new Date(scheduled_date).toISOString().slice(0, 19).replace('T', ' ');
    await db.query('UPDATE announcements SET title = ?, content = ?, scheduled_date = ?, image_path = ? WHERE id = ?', [title, content, formattedDate, imagePath, id]);
    res.status(200).json({ message: 'Announcement updated successfully' });
  } catch (error) {
    console.error('Error updating announcement:', error);
    res.status(500).json({ error: 'Failed to update announcement' });
  }
});



/////////////////////////candidate-stats//////////////////////////////////////////////
app.get('/api/candidate-stats', async (req, res) => {
  const { schoolId } = req.query;

  try {
    const [houseRepStats] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, hr.vote_count
       FROM candidates c
       JOIN hostelrep_votes hr ON c.id = hr.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE s.idschools = ?`, [schoolId]
    );

    const [delegateStats] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, d.vote_count
       FROM candidates c
       JOIN delegates_votes d ON c.id = d.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE s.idschools = ?`, [schoolId]
    );

    const [congresspersonStats] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, cp.vote_count
       FROM candidates c
       JOIN congressperson_votes cp ON c.id = cp.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE s.idschools = ?`, [schoolId]
    );

    res.json({
      houseRepStats,
      delegateStats,
      congresspersonStats,
    });
  } catch (error) {
    console.error('Error fetching candidate stats:', error);
    res.status(500).json({ message: 'Server error' });
  }
});




app.get('/api/presidential-winner', async (req, res) => {
  try {
    const [winningParty] = await db.query(`
      SELECT p.id, p.party_name, COUNT(pv.id) AS voteCount
      FROM presidential_votes pv
      JOIN parties p ON pv.party_id = p.id
      GROUP BY p.id
      ORDER BY voteCount DESC
      LIMIT 1
    `);

    if (winningParty.length === 0) {
      return res.status(404).json({ message: 'No winning party found' });
    }

    const [partyLeaders] = await db.query(`
      SELECT l.name, l.position, l.image
      FROM leaders l
      WHERE l.party_id = ?
    `, [winningParty[0].id]);

    res.json({ party: winningParty[0], leaders: partyLeaders });
  } catch (error) {
    console.error('Error fetching presidential winner:', error);
    res.status(500).json({ message: 'Server error' });
  }
});




////////////////////////////////////////School Managament///////////////////////////////////
app.get('/api/schoolsmanagement', async (req, res) => {
  try {
    const query = `
      SELECT sm.school_id, sm.congressperson, sm.delegate, s.schoolname
      FROM schoolsmanagement sm
      JOIN schools s ON sm.school_id = s.idschools
    `;
    
    // Await the query result
    const [results] = await db.query(query);

    // Send the results as JSON
    res.json(results); 
  } catch (err) {
    console.error('Error fetching data:', err);
    res.status(500).json({ message: 'Error fetching data' });
  }
});


// PUT /api/admin/schoolmanagement
app.put('/api/admin/schoolsmanagement', async (req, res) => {
  const updatedSchools = req.body;  // Get updated data from the client
  
  try {
    for (const school of updatedSchools) {
      // First, check if the school exists in the schoolsmanagement table
      const [existingSchool] = await db.execute(
        'SELECT * FROM schoolsmanagement WHERE school_id = ?',
        [school.school_id]
      );

      // If school doesn't exist, insert it; else update it
      if (existingSchool.length === 0) {
        // Insert the new school data with default values for congressperson and delegate
        await db.execute(
          'INSERT INTO schoolsmanagement (school_id, congressperson, delegate) VALUES (?, ?, ?)',
          [school.school_id, school.congressperson || 0, school.delegate || 0]
        );
      } else {
        // Update the existing school data
        await db.execute(
          'UPDATE schoolsmanagement SET congressperson = ?, delegate = ? WHERE school_id = ?',
          [school.congressperson || 0, school.delegate || 0, school.school_id]
        );
      }
    }

    res.status(200).send('Changes saved successfully!');
  } catch (err) {
    console.error('Error updating schools:', err);
    res.status(500).send('Error updating schools');
  }
});



///////////////////////////////////////////////////////
app.get("/campuses", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM campuses");
    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching campuses:", err);
    res.status(500).json({ message: "Error fetching campuses" });
  }
});

// Update campus population and representatives
app.put("/campuses/:id", async (req, res) => {
  const { id } = req.params;
  const { population } = req.body;

  if (typeof population !== "number") {
    return res.status(400).json({ message: "Invalid population value" });
  }

  try {
    // Determine representatives based on population
    let representatives = [];
    if (population < 300) {
      representatives = ["Campus Congressperson"];
    } else if (population <= 500) {
      representatives = ["Male Campus Congressperson", "Female Campus Congressperson"];
    } else {
      representatives = [
        "Campus Representative",
        "Male Campus Congressperson",
        "Female Campus Congressperson",
      ];
    }

    // Update the database
    const [result] = await db.query(
      "UPDATE campuses SET population = ?, representatives = ? WHERE id = ?",
      [population, JSON.stringify(representatives), id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Campus not found" });
    }

    res.status(200).json({ message: "Campus updated successfully", representatives });
  } catch (err) {
    console.error("Error updating campus:", err);
    res.status(500).json({ message: "Error updating campus" });
  }
});


app.post('/api/generate-token', async (req, res) => {
  const { voterId, candidateType } = req.body;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name for the current year

  // Log the received request data to check if the body is correct
  console.log('Received voterId:', voterId, 'candidateType:', candidateType);

  if (!voterId || !candidateType) {
    return res.status(400).json({ error: 'Voter ID and Candidate Type are required' });
  }

  try {
    // Hash the voter ID using SHA-256 for security
    const hashedVoterId = crypto.createHash('sha256').update(voterId).digest('hex');
    console.log('Hashed Voter ID:', hashedVoterId); // Log the hashed voter ID to verify

    // Generate a unique voting token
    const token = crypto.randomBytes(16).toString('hex');
    console.log('Generated Token:', token); // Log the generated token for debugging

    // Insert hashed voter ID, token, and candidate type into the database
    const result = await db.execute(
      `INSERT INTO ${schemaName}.voting_tokens (token, candidate_type, hashed_voter_id) VALUES (?, ?, ?)`,
      [token, candidateType, hashedVoterId]
    );
    
    // Log the result of the database insertion
    console.log('Database insert result:', result);

    // Return the token to the client
    res.status(200).json({ token });
  } catch (error) {
    console.error('Error generating token:', error.message);
    res.status(500).json({ error: 'Failed to generate token. Please try again later.' });
  }
});

// Cast Vote Endpoint
app.post('/api/vote', async (req, res) => {
  const { email, candidateId, candidateType } = req.body;

  if (!email || !candidateId || !candidateType) {
    return res.status(400).json({ error: 'Email, Candidate ID, and Candidate Type are required' });
  }

  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name for the current year

  try {
    // Check if the user has already voted for this candidate type
    const [existingVote] = await db.execute(
      `SELECT * FROM ${schemaName}.full_votes WHERE user_email = ? AND candidate_type = ?`,
      [email, candidateType]
    );

    if (existingVote.length > 0) {
      return res.status(400).json({ error: 'You have already voted for this type of candidate.' });
    }

    // Insert the vote into the database
    const query = `
      INSERT INTO ${schemaName}.full_votes (user_email, candidate_id, candidate_type) 
      VALUES (?, ?, ?)
    `;
    await db.execute(query, [email, candidateId, candidateType]);

    res.status(200).json({ message: 'Vote cast successfully!' });
  } catch (error) {
    console.error('Error casting vote:', error.message);
    res.status(500).json({ error: 'Failed to cast vote. Please try again later.' });
  }
});


app.get('/api/congressperson', async(req,res) => {
  try{
    const [congressroles] = await db.query('SELECT * FROM congresspersonroles');

    res.json(congressroles)
  }catch(error){
    console.error('Error')
    
  }
} )


app.get('/api/admin/congressvote-stats/congressperson/:id', async (req, res) => {
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name

  const { id } = req.params;
  console.log('Received candidateType ID:', id);  // Debugging log

  const roleQuery = 'SELECT congressname FROM congresspersonroles WHERE id = ?';
  const voteQuery = `
  SELECT 
    fv.candidate_id, 
    c.name AS candidate_name, 
    fv.candidate_type, 
    COUNT(*) AS vote_count
  FROM 
    ${schemaName}.full_votes fv
  JOIN 
    ${schemaName}.candidates c ON fv.candidate_id = c.id
  WHERE 
    fv.candidate_type = ? 
  GROUP BY 
    fv.candidate_id, 
    fv.candidate_type, 
    c.name
  ORDER BY 
    vote_count DESC;
`;



  try {
    console.log('Executing role query...');  // Debugging log

    // Fetch the candidate type name
    const [roleResults] = await db.query(roleQuery, [id]);
    console.log('Role Query executed successfully, results:', roleResults);  // Debugging log

    if (roleResults.length === 0) {
      console.warn('Candidate type not found for ID:', id);  // Debugging log
      return res.status(404).send({ message: 'Candidate type not found' });
    }

    const candidateTypeName = roleResults[0].congressname;
    console.log('Candidate type name:', candidateTypeName);  // Debugging log

    console.log('Executing vote query...');  // Debugging log

    // Fetch the vote statistics
    const [voteResults] = await db.query(voteQuery, [candidateTypeName]);
    console.log('Vote Query executed successfully, results:', voteResults);  // Debugging log

    res.json(voteResults);

  } catch (err) {
    console.error('Database Query Error:', err);  // Debugging log
    res.status(500).send(err);
  }
});

app.post('/api/campus-vote', async (req, res) => {
  const { userEmail, candidateId, campusName,campusId } = req.body;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name

  // Validate request
  if (!userEmail || !candidateId || !campusName) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Insert or update the vote using ON DUPLICATE KEY UPDATE
    const result = await db.query(
      `INSERT INTO ${schemaName}.campuses_votes (user_email, candidate_id, campus_name,campus_id) 
       VALUES (?, ?, ?,?)`, 
      [userEmail, candidateId, campusName,campusId]
    );

    // Check affectedRows for confirmation
    if (result.affectedRows === 1) {
      // A new vote was inserted
      return res.status(200).json({ message: 'Vote cast successfully!' });
    } else if (result.affectedRows === 2) {
      // An existing vote was updated (this means they changed their vote)
      return res.status(200).json({ message: 'Your vote has been updated successfully!' });
    }

  } catch (err) {
    console.error('Error casting vote:', err.message || err);
    return res.status(500).json({ error: 'Failed to cast vote' });
  }
});

app.get('/api/stats/campus-vote-stats/campus/:campusId', async (req, res) => {
  const campusId = req.params.campusId;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`; // Dynamic schema name

  console.log('Received campus id:', campusId); // Debugging log

  if (!campusId) {
    return res.status(400).json({ message: 'Campus ID is required' });
  }

  // Query to get vote stats by campus ID and include candidate names
  const query = `
    SELECT 
      cv.candidate_id,
      c.name AS candidate_name,
      COUNT(*) AS vote_count
    FROM 
      ${schemaName}.campuses_votes cv
    JOIN 
      ${schemaName}.candidates c ON cv.candidate_id = c.id
    WHERE 
      cv.campus_id = ?
    GROUP BY 
      cv.candidate_id, c.name
    ORDER BY 
      vote_count DESC
  `;

  try {
    const [results] = await db.execute(query, [campusId]);

    if (results.length === 0) {
      return res.status(404).json({ message: `No vote stats found for campus: ${campusId}` });
    }

    console.log('Raw results:', results); // Debugging log

    res.json(results); // Send the results including candidate names to the frontend
  } catch (error) {
    console.error('Error fetching campus vote stats:', error);
    res.status(500).json({ message: 'An error occurred while fetching campus stats.' });
  }
});


app.get("/api/admin/users", async (req, res) => {
  try {
    const [users] = await db.query("SELECT * FROM users");
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Verify user
app.put("/api/admin/users/verify/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await db.query("UPDATE users SET isVerified = '1' WHERE id = ?", [id]);
    res.json({ message: "User verified successfully" });
  } catch (error) {
    console.error("Error verifying user:", error);
    res.status(500).json({ message: "Server error" });
  }
});



app.put("/api/admin/users/disable/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { disabled } = req.body;  // Assuming you are sending "disabled" as a boolean

    // Update the user's disabled status in the database
    await db.query("UPDATE users SET status_disabled = ? WHERE id = ?", [disabled, id]);

    // Fetch the user's email
    const [user] = await db.query("SELECT email FROM users WHERE id = ?", [id]);

    // Ensure user email is present
    if (!user || !user[0].email) {
      console.error("No email found for the user.");
      return res.status(400).json({ message: "Email not found." });
    }

    const userEmail = user[0].email;  // Correctly accessing the email

    console.log(userEmail);  // Log email to verify it's correct

    // Set up email data using the transporter you already have
    const mailOptions = {
      from: 'mikekariuki10028@gmail.com',  // sender address (use your email here)
      to: userEmail,                      // recipient's email (user's email)
      subject: 'Your Account Has Been Disabled',  // email subject
      text: `Dear User,

Your account has been ${disabled ? 'disabled' : 'enabled'}.

If this was a mistake, please contact support.

Best regards,
Your Team`, // plain text email body
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    // Respond with a success message
    res.json({ message: `User ${disabled ? "disabled" : "enabled"} successfully` });
  } catch (error) {
    console.error("Error updating user status:", error);
    res.status(500).json({ message: "Error updating user status." });
  }
});

// Delete user
app.delete("/api/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await db.query("DELETE FROM users WHERE id = ?", [id]);
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "Server error" });
  }
});








app.get('/', (req, res) => {
  res.send('Hello, World!');
});



app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});