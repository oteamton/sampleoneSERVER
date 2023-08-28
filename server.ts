import express, { Request, Response } from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import crypto = require('crypto');
import bcrypt = require('bcrypt');
const app = express();
const port = 5000;

const registeredUsers: any[] = [];
const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds);

// Function to check if username or email already exist
function checkIfUserExists(username: string, email: string) {

    if (registeredUsers.find(user => user.username === username)) {
        return 'Username already been taken.';
    }

    if (registeredUsers.find(user => user.email === email)) {
        return 'Email already been registered.';
    }

    return null; // No conflicts
}

app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON body

// Endpoint for GET request
app.get('/', (req: Request, res: Response) => {
    res.send(`test server! ${port} Users Data: ${JSON.stringify(registeredUsers)}`);
});

// Endpont for POST request
app.post('/register', (req: Request, res: Response) => {
    const { username, password, email } = req.body;
    // Handle registration logic
    // Basic validation checks
    if (!username || !password || !email){
        return res.status(400).json({ error: 'All fields are required.'});
    }

    // Check for conflicts
    const conflict = checkIfUserExists(username, email);
    if (conflict) {
        return res.status(409).json({ error: conflict});
    }

    // // Check email is already taken
    // const existingEmail = registeredUsers.find(user => user.email === email);
    // if(existingEmail){
    //     return res.status(409).json({ error: 'Email already been registered.'});
    // }
    // // Check if username is already taken
    // const existingUser = registeredUsers.find(user => user.username === username);
    // if(existingUser){
    //     return res.status(409).json({ error: 'Username already been taken.'});
    // }

    // Create a user object with registration data
    const newUser = {
        username: username,
        hashedPassword: bcrypt.hashSync(password, salt),
        email: email,
        secretKey: crypto.randomBytes(64).toString('hex'),
    };

    // // Generate a secret key for JWT
    // const secretKey: string = crypto.randomBytes(64).toString('hex');

    // Create a JWT with expiration time in 1 hour
    // const token = jwt.sign(newUser, secretKey, { expiresIn: '1h' });

    // Add new user object to the array
    registeredUsers.push(newUser);

    res.status(201).json({ message: 'Registration successful!'});
});

// Endpoint for GET users endpoint
app.get('/users', (req: Request, res: Response) => {
    res.json(registeredUsers);
})

// Endpoint for POST login endpoint
app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    const user = registeredUsers.find(user => user.username === username);
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password.'});
    }

    const isPasswordValid = bcrypt.compareSync(password, user.hashedPassword);

    if (!isPasswordValid) {
        return res.status(401).json({ error: 'Invalid username or password.'});
    }

    const token = jwt.sign({ username: user.username }, user.secretKey, { expiresIn: '1h' });
    
    res.status(200).json({ message:'Login successful' ,token });
})

app.listen(port, () => {
    console.log(`Server is runnning on port ${port}`);
});