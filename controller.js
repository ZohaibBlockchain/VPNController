const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const axios = require('axios');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const adminToken = process.env.ADMIN_TOKEN;



var serviceAccount = require("./fb.json");
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.DATABASE
});

//Init database
const db = admin.database();



// Configure NodeMailer with your custom SMTP server details
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST, // Your custom mail server's hostname or IP address
    port: process.env.EMAIL_PORT, // Commonly used port for SMTP
    secure: false, // True if using 465, false for other ports
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});



// Create Express App
const app = express();

// Middleware
app.use(bodyParser.json());


// Start the Server
const PORT = process.env.PORT || 6500;
app.listen(PORT, () => {
    console.log(`SecureScape Controller running on port ${PORT}`);
});




const Limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 requests per windowMs
    message: 'Too many attempts from this IP, please try again after 15 minutes.'
});




// Routes
app.get('/', (req, res) => {
    res.json('This is a SecureScape Controller endpoint');
});



// Routes
app.get('/api/serverlist', async (req, res) => {

    if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    const idToken = req.headers.authorization.split('Bearer ')[1];
    const info = await decodeIdToken(idToken);

    const ref = db.ref('serverList');
    // Fetch data once
    ref.get()
        .then((snapshot) => {
            const data = snapshot.val();
            console.log('data:', data); // Log the retrieved data
            res.json(data); // Send the retrieved data as JSON response
        })
        .catch((error) => {
            console.error('Error fetching data:', error); // Log any errors
            res.status(500).send('Error fetching data'); // Send an error response if fetching data fails
        });
});




app.post('/api/selectedserver', async (req, res) => {
    try {
        const { serverID } = req.body;

        // Check if the authorization header is present and has the correct format
        if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        // Extract the ID token from the authorization header
        const idToken = req.headers.authorization.split('Bearer ')[1];

        // Decode the ID token to get user information
        const userInfo = await decodeIdToken(idToken);

        // Set the selected server for the user in the database
        const userRef = db.ref('usrData').child(userInfo.uid);
        await userRef.set({ selectedServer: serverID });


        //Futher send request to other service to add this peer







        res.status(200).json({ message: 'Server selected successfully' });
    } catch (error) {
        console.error('Error selecting server:', error);
        res.status(500).json({ message: 'Error selecting server' });
    }
});





app.post('/api/addnewserver', (req, res) => {
    const { endpoint, publickey } = req.body;
    res.status(201).json(enpoint, publickey);
});


app.post('/api/signup', Limiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    if (email.length < 6 || password.length < 8) {
        return res.status(400).json({ error: 'Email must be at least 6 characters long and password must be at least 8 characters long.' });
    }
    // Additional password strength validation can be added here

    try {
        const user = await admin.auth().createUser({
            email: email,
            password: password,
            emailVerified: true,
            disabled: false
        });
        res.status(201).json({ message: 'User created successfully', user });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.post('/api/login',Limiter, async (req, res) => {
    const { email, password } = req.body;
    const apiKey = 'aa'; // Replace with your Firebase API key
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;

    console.log(email,password);
    try {
        const response = await axios.post(url, {
            email,
            password,
            returnSecureToken: true
        });

        const { idToken, refreshToken, expiresIn } = response.data;
        // You might want to set a session cookie or generate a session token here
        res.status(200).json({ idToken, refreshToken, expiresIn });

    } catch (error) {
        res.status(400).json({ message: 'Authentication failed', error: error });
    }
});




const checkAuth = async (req, res, next) => {
    if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    const idToken = req.headers.authorization.split('Bearer ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = decodedToken; // Attach user info to the request
        next(); // Proceed to the next middleware or request handler
    } catch (error) {
        res.status(403).json({ message: 'Invalid token', error: error.message });
    }
};


const checkAdmin = async (req, res, next) => {
    if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    const idToken = req.headers.authorization.split('Bearer ')[1];
    try {
        if (adminToken === idToken) {
            next(); // Proceed to the next middleware or request handler
        } else {
            res.status(403).json({ message: 'Invalid token' });
        }
    } catch (error) {
        res.status(403).json({ message: 'Invalid token', error: error.message });
    }
};




// Function to generate a random code
function generateResetCode() {
    return crypto.randomBytes(3).toString('hex');  // Generates a 6-digit hexadecimal code
}



const checkUserExists = async (req, res, next) => {
    const { email } = req.body;

    try {
        const userRecord = await admin.auth().getUserByEmail(email);
        next(); // Proceed to the next middleware or request handler
    } catch (error) {
        // If the user does not exist, an error will be thrown
        if (error.code === 'auth/invalid-email') {
            res.status(404).json({ exists: 'User not exits' });
        } else {
            // Handle other possible errors
            res.status(500).json({ error: error });
        }
    }
};




app.post('/api/request-reset', checkUserExists, async (req, res) => {
    const { email } = req.body;
    try {
        const code = generateResetCode();
        // Store the code in your database with an expiration time
        // Example: saveCodeForUser(email, code, expirationTime);

        // Send the code via email
        const mailOptions = {
            from: 'zohaib@flashledger.net',
            to: email,
            subject: 'Your Password Reset Code',
            text: `Your password reset code is: ${code}`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).send('Reset code sent to your email.');
    } catch (error) {
        console.log(error);
        res.status(500).send('Failed to send reset code.');
    }
});





app.post('/api/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;
    try {
        // Verify the code and check expiration
        // Example: const isValid = await verifyResetCode(email, code);
        if (!isValid) {
            return res.status(400).send('Invalid or expired reset code.');
        }

        // Update the password in Firebase Auth
        const user = await admin.auth().getUserByEmail(email);
        await admin.auth().updateUser(user.uid, {
            password: newPassword
        });

        // Optionally, invalidate the code after use
        // Example: invalidateCode(email, code);

        res.status(200).send('Password has been reset successfully.');
    } catch (error) {
        console.log(error);
        res.status(500).send('Failed to reset password.');
    }
});



app.post('/api/addServer', checkAdmin, async (req, res) => {
    try {
        const { publicKey, endPoint, myAddress, DNS, name, region, ID } = req.body;
        if (publicKey && endPoint && myAddress && DNS && name && region && ID) {
            const config = {
                Info: {
                    Name: name,
                    Region: region
                },
                Interface: {
                    Address: myAddress,
                    DNS: DNS
                },
                Peer: {
                    PublicKey: publicKey,
                    Endpoint: endPoint,
                    AllowedIPs: '0.0.0.0/0, ::/0'
                }
            };

            const ref = db.ref('serverList').child(ID); // Using child() to specify ID
            await ref.set(config); // Using set() instead of push() to overwrite existing data

            res.status(200).send('Successfully added new server.');
        } else {
            res.status(400).json('Missing Config Key');
        }
    } catch (error) {
        res.status(400).json(error);
    }
});



app.delete('/api/removeServer/:id', checkAdmin, async (req, res) => {
    try {
        const serverId = req.params.id;

        if (!serverId) {
            return res.status(400).json('Missing server ID');
        }

        const ref = db.ref('serverList').child(serverId);

        ref.remove()
            .then(() => {
                res.status(200).send('Successfully removed server.');
            })
            .catch((error) => {
                console.error('Error removing server:', error);
                res.status(500).send('Error removing server.');
            });
    } catch (error) {
        console.error('Error removing server:', error);
        res.status(500).send('Error removing server.');
    }
});



app.get('/api/protected', checkAuth, (req, res) => {
    res.status(200).json({ message: 'Access to protected data', user: req.user });
});










// Verify ID token and decode user information
async function decodeIdToken(idToken) {
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const uid = decodedToken.uid;
        const email = decodedToken.email;
        // Additional user information available in decodedToken
        return { uid, email };
    } catch (error) {
        console.error('Error verifying ID token:', error);
        return null;
    }
}