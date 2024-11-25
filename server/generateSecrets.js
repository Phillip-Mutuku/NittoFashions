const crypto = require('crypto');

function generateSecrets() {
    const jwtSecret = crypto.randomBytes(32).toString('hex');
    const sessionSecret = crypto.randomBytes(32).toString('hex');

    console.log('\nCopy these values to your .env file:\n');
    console.log(`JWT_SECRET=${jwtSecret}`);
    console.log(`SESSION_SECRET=${sessionSecret}\n`);

    // Also show how the .env file should look
    console.log('Your .env file should contain these lines:');
    console.log('----------------------------------------');
    console.log(`JWT_SECRET=${jwtSecret}`);
    console.log(`SESSION_SECRET=${sessionSecret}`);
    console.log('----------------------------------------\n');
}

generateSecrets();