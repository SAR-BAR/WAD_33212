const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

//Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/mern_auth', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Error connecting to MongoDB:', err));

//Define use schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String
});

//Define user model
const User = mongoose.model('User', userSchema);

//Middleware to parse JSON bodies
app.use(express.json());
app.use(cors());

//Register route
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        //Check if username already exists 
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }
        //Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        //Create new user
        const newUser = new User({
            username,
            password: hashedPassword
        });
        await newUser.save();

        res.status(201).json({ message: 'User Registration Successful' });

    } catch (error) {
        console.error('Error registraing user: ', error);
        res.status(500).json({ message: 'Internal server error ' });
    }
});

//Login route
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        //Find user by username
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username' });
        }

        //Check password 
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid username or password ' });
        }

        //Generate JWT token
        const token = jwt.sign({ username: user.username }, 'secret_key');
        res.json({ token });
    } catch (error) {
        console.error('Error logging in: ', error);
        res.status(500).json({ message: 'Internal Server Error ' });
    }
});

//Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = aithHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401);
    }
    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

//start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log('Server is running on port ${PORT}');
});
