import nodemailer from 'nodemailer';

// Create a transporter object
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'zelazideqc@gmail.com',
        pass: 'Ton26052543'
    }
});

// Function to send an authentication email
function sendAuthEmail(username: string, email: string, token: string) {
    const mailOptions = {
        from: '"Sample One Server" <zelazideqc@gmail.com>',
        to: email,
        subject: 'Authentication',
        text: `Please click on the following link to verify your account: ${token}`
    }


    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}



// Send an authentication email
const userEmail = 'zelazideqc@gmail.com';
const activationToken = 'token';
sendAuthEmail(userEmail, activationToken, activationToken);
