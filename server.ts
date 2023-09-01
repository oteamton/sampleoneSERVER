import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import jwt, { JwtPayload } from 'jsonwebtoken';
import crypto = require('crypto');
import bcrypt = require('bcrypt');
import nodemailer, { Transporter } from 'nodemailer';

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

    if (registeredUsers.find(user => user.email === email)) {
        return 'Email already been registered.';
    }

    if (registeredUsers.find(user => user.username === username)) {
        return 'Username already been taken.';
    }

    return null; // No conflicts
}

// Function to check if a token is valid and not expired
function checkTokenValidity(token: string): boolean {
    const decodedToken = jwt.decode(token) as { exp: number } | null;

    if (decodedToken) {
        const expirationTime = decodedToken.exp * 1000;
        return Date.now() < expirationTime;
    }
    return false;
}

// Create a transporter object
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your_email',
        pass: 'password'
    }
})

// Function to send an authentication email
function sendAuthEmail(username: string, email: string, activationToken: string) {
    const mailOptions = {
        from: '"Sample One Server" <kitchanunt@g.swu.ac.th>',
        to: email,
        subject: 'Authentication',
        html: `<p>Hi ${username},</p>
               <p>Click on the following link to verify your account: <a href="http://localhost:5000/activate/${activationToken}">Verify Account</a></p>`
    }

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON body

// Access to array to see the data
app.get('/', (req: Request, res: Response) => {
    res.send(`test server! ${port} Users Data: ${JSON.stringify(registeredUsers)} LoggedIn Users Data: ${JSON.stringify(loggedInUsers)}`);
});

// Verify token and store user
app.get('/activate/:token', (req: Request, res: Response) => {
    const activationToken = req.params.token;

    // Verify token
    try {
        const decodedToken: any = jwt.verify(activationToken, registeredUsers[0].secretKey) as { username: string, };
        const username = decodedToken.username;

        // Find user in registeredUsers array
        const user = registeredUsers.find(user => user.username === username);

        if (user) {
            // Store user in loggedInUsers array
            const verifiedUser = {
                username: user.username,
                hasedPassword: user.hashedPassword,
                token: user.activationToken
            };
            loggedInUsers.push(verifiedUser);
        } else {
            // User not found
            return res.status(404).json({ error: 'User not found.' });
        }
        
        // Send response
        res.status(200).json({ message: 'Account activated successfully' });
    } catch (error) {
        res.status(400).send('Invalid or expired token');
    
}
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

    // Generate secret key
    const secretKey = crypto.randomBytes(64).toString('hex');

    // Generate a JWT token
    const activationToken = jwt.sign({ username: username }, secretKey, { expiresIn: '5m' });

    // Create a user object with registration data
    const newUser = {
        username: username,
        hashedPassword: bcrypt.hashSync(password, salt),
        email: email,
        activationToken: activationToken,
        secretKey: secretKey
    };
    // Add the user to the array
    registeredUsers.push(newUser);

    // Send an authentication email
    sendAuthEmail(username, email, activationToken);

    res.status(201).json({ message: 'Registration success'});
});

// Endpoint for GET users endpoint
app.get('/users', (req: Request, res: Response) => {
    res.json(registeredUsers);
});

// Endpoint for POST login
app.post('/login', (req: CustomRequest, res: Response) => {
    const { username, password } = req.body;
    const verifiedUser = loggedInUsers.find(user => user.username === username);

    if ( !username || !password) {
        return res.status(400).json({ error: 'Please fill in username and password.'});
    }

    if (!verifiedUser) {
        return res.status(401).json({ error: 'User not found.' });
    }
    
    const isPasswordValid = bcrypt.compareSync(password, registeredUsers[0].hashedPassword);
    if (!isPasswordValid) {
        return res.status(401).json({ error: 'Incorrect password.'});
    }

    return res.status(200).json({ result:'Login successful'});

    // const token = jwt.sign({ username: user.username }, 'secretKey', { expiresIn: '10s' });

    // Decode the token (without verification)
    // const decodedToken = jwt.decode(token) as { exp: number } | null;
    
    // if (decodedToken) {
    //     const expirationTime = decodedToken.exp;
        
    //     if (Date.now() > expirationTime) {
    //         // Token has expired
    //         console.log('Token has expired.');
    //         return res.status(401).json({ result: 'Token has expired.'});
    //     } else {
    //         // Token is still valid
    //         console.log('Token is still valid.');
    //         const expDate = new Date(expirationTime);
    //         return res.status(200).json({ result:'Login successful' ,token });
    //     }
    // } else {
    //     // Invalid token or unable to decode
    //     console.log('Invalid token or unable to decode.');
    // }
});

// Check for token
// app.use((req: CustomRequest, res: Response, next: Function) => {
//     const token = req.headers.authorization?.split(' ')[1];

//     if (token) {
//         try {
//             // Verify the token
//             const decodedToken = jwt.verify(token, 'secretKey') as JwtPayload;
//             const username = decodedToken.sub as string;
//             const loggedInUserIndex = loggedInUsers.findIndex(
//                 user => user.username === decodedToken.username
//             );

//             if (loggedInUserIndex >= 0) {
//                 // Token is still valid
//                 req.user = { username };
//                 next();
//             } else {
//                 // Token has expired
//                 res.status(401).json({ result: 'Token has expired.'});
//             }
//     } catch (err) {
//         res.status(401).json({ result: 'Invalid token.'});
//     }
//     } else {
//         res.status(401).json({ result: 'No token provided.'}); 
//     }
// });

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