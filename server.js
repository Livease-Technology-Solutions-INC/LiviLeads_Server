import express from 'express';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import User from './user.js';
import jwt from 'jsonwebtoken';
import cors from 'cors';
dotenv.config();
const app = express();
const port = process.env.PORT;
const whitelist = ['http://localhost:3000'];
const invalidTokens = [];
if (!process.env.JWT_SECRET) {
	console.error('JWT_SECRET is not defined in the environment variables.');
	process.exit(1); 
}
const corsOptions = {
	origin: (origin, callback) => {
		// Check if the origin is in the whitelist or if it's a same-origin request
		if (whitelist.includes(origin) || !origin) {
			callback(null, true);
		} else {
			callback(new Error('Not allowed by CORS'));
		}
	},
	methods: ['GET', 'POST', 'PUT', 'DELETE'],
	optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

const connectToMongoDB = async () => {
	try {
		await mongoose.connect(process.env.MONGO_URI, {
			serverSelectionTimeoutMS: 5000,
		});
		console.log('MongoDB Connected');
	} catch (error) {
		console.error('MongoDB Connection Error:', error.message);
	}
};

connectToMongoDB();
app.use(express.json());

app.post('/register', async (req, res) => {
	const { username, email, password } = req.body;

	try {
		// Check if the email is already registered
		const existingUser = await User.findOne({ email }).maxTimeMS(20000);
		

		if (existingUser) {
			// Return 409 status if the email is already registered
			return res.status(409).json({ message: 'Email already registered' });
		}
		// Hash the password
		const hashedPassword = await bcrypt.hash(password, 10);

		// Check if the username is already in use
		const existingUsername = await User.findOne({ username }).maxTimeMS(20000);

		if (existingUsername) {
			// Return 409 status if the username is already in use
			return res.status(409).json({ message: 'Invalid credentials' });
		}
		// Save the user to MongoDB
		const newUser = new User({ username, email, password: hashedPassword });
		await newUser.save();
		// After successful registration, generate a token
		const token = generateToken(newUser._id, newUser.email);

		res.status(201).json({ message: 'User registered successfully', token });
	} catch (error) {
		console.error(error);
		res.status(500).json({ message: 'Internal server error' });
	}
});
app.post('/login', async (req, res) => {
	const { email, password } = req.body;

	try {
		// Check if the user exists in the database
		const user = await User.findOne({ email }).maxTimeMS(20000);

		// Verify the password
		if (!user || !(await bcrypt.compare(password, user.password))) {
			return res.status(401).json({ message: 'Invalid credentials' });
		}

		const secretKey = process.env.JWT_SECRET;
		// After successful login, generate a token
		const token = generateToken(user._id, user.email);

		// Send a successful login message with the token
		res.status(200).json({ message: 'Login successful', token });
	} catch (error) {
		console.error(error);
		res.status(500).json({ message: 'Internal server error' });
	}
});
app.post('/logout', (req, res) => {
	const { token } = req.body;

	try {
		if (!token) {
			return res
				.status(401)
				.json({ message: 'Unauthorized - No token provided' });
		}

		invalidTokens.push(token);

		res.status(200).json({ message: 'Logout successful' });
	} catch (error) {
		console.error(error);
		res
			.status(500)
			.json({ message: 'Internal server error', error: error.message });
	}
});

app.get('/test', (req, res) => {
	res.json('working');
});
// JWT token generation function
function generateToken(userId, userEmail) {
	const secretKey = process.env.JWT_SECRET || 'your-secret-key';
	const token = jwt.sign({ userId, email: userEmail }, secretKey, {
		expiresIn: '5m',
	});
	return token;
}
// Error handling middleware
app.use((err, req, res, next) => {
	console.error(err.stack);
	res.status(500).json({ message: 'Internal server error' });
});

const startServer = async () => {
	await connectToMongoDB();

	app.listen(port, () => {
		console.log(`Server is running on port ${port}`);
	});
};

startServer();
