import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import jwt, { JwtPayload } from 'jsonwebtoken';
import crypto = require('crypto');
import bcrypt = require('bcrypt');

// Define a custom interface that extends the default request interface
interface CustomRequest extends Request {
    user?: { username: string };
}
const app = express();
const port = 5000;
// Array of registered users
const registeredUsers: any[] = [];
// Array of logged in users
const loggedInUsers: { username: string, token: string }[] = [];
// Salt rounds
const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds); // Generate a salt

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
app.use((req: CustomRequest, res: Response, next: Function) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (token) {
        try {
            // Verify the token
            const decodedToken = jwt.verify(token, 'secretKey') as JwtPayload;
            const loggedInUserIndex = loggedInUsers.findIndex(
                user => user.username === decodedToken.username
            );

            if (loggedInUserIndex >= 0) {
                // Token is still valid
                req.user = decodedToken;
                next();
            } else {
                // Token has expired
                res.status(401).json({ result: 'Token has expired.'});
            }
    } catch (err) {
        res.status(401).json({ result: 'Invalid token.'});
    }
    } else {
        res.status(401).json({ result: 'No token provided.'}); 
    }
});

// Endpoint for GET request
app.get('/', (req: Request, res: Response) => {
    res.send(`test server! ${port} Users Data: ${JSON.stringify(registeredUsers)}`);
});

// Endpont for POST registration
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

    // Create a user object with registration data
    const newUser = {
        username: username,
        hashedPassword: bcrypt.hashSync(password, salt),
        email: email,
    };

    registeredUsers.push(newUser);

    res.status(201).json({ message: 'Registration successful!'});
});

// Endpoint for GET users endpoint
app.get('/users', (req: Request, res: Response) => {
    res.json(registeredUsers);
});

// Endpoint for POST login
app.post('/login', (req: CustomRequest, res: Response) => {
    const { username, password } = req.body;
    const user = registeredUsers.find(user => user.username === username);
    if (!user) {
        return res.status(401).json({ result: 'No user found. Please sign up.'});
    }
    
    const isPasswordValid = bcrypt.compareSync(password, user.hashedPassword);
    if (!isPasswordValid) {
        return res.status(401).json({ result: 'Incorrect password.'});
    }

    const token = jwt.sign({ username: user.username }, 'secretKey', { expiresIn: '10s ' });

    // Decode the token (without verification)
    const decodedToken = jwt.decode(token) as { exp: number } | null;
    
    if (decodedToken) {
        const expirationTime = decodedToken.exp * 1000;
        
        if (Date.now() > expirationTime) {
            // Token has expired
            console.log('Token has expired.');
        } else {
            // Token is still valid
            console.log('Token is still valid.');
        }
    } else {
        // Invalid token or unable to decode
        console.log('Invalid token or unable to decode.');
    }

    res.status(200).json({ result:'Login successful' ,token });
});

// Endpoint for POST logout
app.post('/logout', (req: CustomRequest, res: Response) => {
    const { username } = req.user as { username: string };
    const loggedInUserIndex = loggedInUsers.findIndex(user => user.username === username);

    if (loggedInUserIndex >= 0) {
        // Remove the user from the array
        loggedInUsers.splice(loggedInUserIndex, 1);
    }

    res.status(200).json({ result:'Logout successful' });
});

app.listen(port, () => {
    console.log(`Server is runnning on port ${port}`);
});