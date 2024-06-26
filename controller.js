const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const axios = require('axios');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const adminToken = process.env.ADMIN_TOKEN;

// Base URL of the API
const apiBaseUrl = process.env.ADMIN_TOKEN;


var serviceAccount = require("./fb.json");
const { type } = require('os');
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
        res.status(403).json({ message: 'Invalid token' });
    }
};

// Create Express App
const app = express();

// Middleware
app.use(bodyParser.json());


// Trust the first proxy
app.set('trust proxy', 1);

// Start the Server
const PORT = process.env.PORT || 6500;
app.listen(PORT, () => {
    console.log(`SecureScape Controller running on port ${PORT}`);
});






const Limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

app.use(Limiter);


// Routes
app.get('/', (req, res) => {
    res.json({ message: 'This is a SecureScape Controller endpoint' });
});



// Routes
app.get('/api/serverlist', checkAuth, async (req, res) => {

    const ref = db.ref('serverList');
    // Fetch data once
    try {
        const _r = await ref.get();

        // Convert the object to an array
        const arrayData = Object.keys(_r.val()).map(key => ({
            ID: key,
            Name: _r.val()[key].Info.Name,
            Region: _r.val()[key].Info.Region
        }));

        console.log(arrayData);
        res.json(arrayData); // Send the retrieved data as JSON response
    } catch (error) {
        // console.error('Error fetching data:', error); // Log any errors
        res.status(500).send({ message: 'Error fetching data' }); // Send an error response if fetching data fails
    }
});




app.get('/api/refresh', checkAuth, async (req, res) => {
    try {
        res.status(200).send({ message: 'ValidToken' }); // Send an error response if fetching data fails
    } catch (error) {
        // console.error('Error fetching data:', error); // Log any errors
        res.status(500).send({ message: 'InValidToken' }); // Send an error response if fetching data fails
    }
});


app.post('/api/selectedserver', checkAuth, async (req, res) => {
    try {
        const { serverID, publicKey } = req.body;

        if (!publicKey) {
            return res.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).json({ message: 'Public key is empty' });
        }

        // Extract the ID token from the authorization header
        const idToken = req.headers.authorization.split('Bearer ')[1];

        // Decode the ID token to get user information
        const userInfo = await decodeIdToken(idToken);

        // Remove the previous server
        const serverlist = db.ref('serverList');
        const _r = await serverlist.get();
        const keys = Object.keys(_r.val());

        // Removing the user from other servers
        await Promise.all(keys.map(async key => {
            const server = _r.val()[key];
            const splitString = server.Peer.Endpoint.split(':');
            const ENDPOINT = splitString[0] + ':14500';

            const userData = db.ref('usrData').child(userInfo.uid);
            const _ud = await userData.get();

            if (_ud.val() && 'publicKey' in _ud.val()) {
                if (publicKey !== _ud.val().publicKey) {
                    const params = {
                        publicKey: _ud.val().publicKey
                    };
                    await axios.post(`http://${ENDPOINT}/api/peer/rm`, params);//previous public key is removed from server
                    const userRef = db.ref('usrData').child(userInfo.uid);
                    await userRef.update({ publicKey: publicKey });//Now here we replaced with new public key
                } else {
                    console.log(_ud.val());
                    const params = {
                        publicKey: publicKey
                    };
                    await axios.post(`http://${ENDPOINT}/api/peer/rm`, params);
                }
            } else {
                //this block will run for the first time user select the server...
                const params = {
                    publicKey: publicKey
                };
                await axios.post(`http://${ENDPOINT}/api/peer/rm`, params);//previous public key is removed from server
                const userRef = db.ref('usrData').child(userInfo.uid);
                await userRef.update({ publicKey: publicKey });
            }
        }));

        const selectedServer = _r.val()[serverID];
        const splitString = selectedServer.Peer.Endpoint.split(':');
        const ENDPOINT = splitString[0] + ':14500';

        // Set the selected server for the user in the database
        const myAddress = await axios.get(`http://${ENDPOINT}/api/available-ip`);
        const userRef = db.ref('usrData').child(userInfo.uid);
        await userRef.update({ myAddress: myAddress.data.availableIP });

        const params = {
            publicKey: publicKey,
            allowedIPs: myAddress.data.availableIP
        };

        const config = {
            Info: {
                serverID: serverID,
                region: selectedServer.Info.Region
            },
            Interface: {
                Address: myAddress.data.availableIP,
                DNS: selectedServer.Interface.DNS
            },
            Peer: {
                PublicKey: selectedServer.Peer.PublicKey,
                AllowedIPs: '0.0.0.0/0, ::/0',
                Endpoint: selectedServer.Peer.Endpoint
            }
        };

        const response = await axios.post(`http://${ENDPOINT}/api/peer`, params);
        console.log(response.data.message);
        if (response.data.message === 'Peer added.' || response.data.message === 'Peer already exists.') {
            console.log(response.data.message);
            res.status(200).json({ message: 'Server selected successfully', config: config });
        } else {
            res.status(500).json({ message: 'Error selecting server', response });
        }
    } catch (error) {
        console.error('Error selecting server:', error);
        res.status(500).json({ message: 'Error selecting server', error });
    }
});



app.post('/api/deactivate', checkAuth, async (req, res) => {


    // Extract the ID token from the authorization header
    const idToken = req.headers.authorization.split('Bearer ')[1];

    try {
        // Decode the ID token to get user information
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const uid = decodedToken.uid;

        // Get the user's email
        const user = await admin.auth().getUser(uid);
        const email = user.email;

        // Sign in with email and password using Firebase Client SDK
        const userCredential = await admin.auth().getUserByEmail(email);

        // Re-authentication successful, proceed to deactivate the user
        await admin.auth().updateUser(userCredential.uid, {
            disabled: true
        });

        res.status(200).json({ message: 'User deactivated successfully' });
    } catch (error) {
        console.error('Error deactivating user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
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



app.post('/api/login', Limiter, async (req, res) => {
    const { email, password } = req.body;
    const apiKey = process.env.FB_API_KEY; // Replace with your Firebase API key
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;
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
            res.status(404).json({ message: 'User not exits' });
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
        const userRecord = await admin.auth().getUserByEmail(email);
        const userRef = db.ref('usrData').child(userRecord.uid);
        await userRef.update({ ResetCode: { code: code, expiry: Date.now() } });

        // Send the code via email
        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Your Password Reset Code',
            text: `Your password reset code is: ${code}`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).send({ message: 'Password reset request successful. Check your email for the reset code.' });
    } catch (error) {
        console.log(error);
        res.status(500).send({ message: 'Failed to send reset code.' });
    }
});



app.post('/api/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;
    try {

        const userRecord = await admin.auth().getUserByEmail(email);
        const userRef = db.ref('usrData').child(userRecord.uid);
        let inf = await userRef.get();

        console.log(inf.val().ResetCode, code, typeof (code), typeof (inf.val().ResetCode), Date.now());

        if (inf.val().ResetCode.code !== code || (inf.val().ResetCode.expiry + (1000 * (5 * 60))) < Date.now()) {
            return res.status(400).send({ error: 'Invalid or expired reset code.' });
        }


        // Update the password in Firebase Auth
        const user = await admin.auth().getUserByEmail(email);
        await admin.auth().updateUser(user.uid, {
            password: newPassword
        });

        // Optionally, invalidate the code after use
        // Example: invalidateCode(email, code);
        // Remove a specific field
        await userRef.update({
            ResetCode: admin.firestore.FieldValue.delete()
        });

        res.status(200).send({ message: 'Password has been reset successfully.' });
    } catch (error) {
        console.log(error);
        res.status(500).send({ message: 'Failed to reset password.' });
    }
});



app.post('/api/addServer', checkAdmin, async (req, res) => {
    try {
        const { publicKey, endPoint, DNS, name, region, ID } = req.body;
        if (publicKey && endPoint && DNS && name && region && ID) {
            const config = {
                Info: {
                    Name: name,
                    Region: region
                },
                Interface: {
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

process.on('uncaughtException', (error) => {
    console.log('Uncaught Exception:', error.message);
    // Optionally, restart the service or perform some other logic here
});

process.on('unhandledRejection', (reason, promise) => {
    console.log('Unhandled Rejection:', reason.message || reason);
    // Optionally, restart the service or perform some other logic here
});








