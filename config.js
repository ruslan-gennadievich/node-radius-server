/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require('fs');
const path = require('path');

const SSL_CERT_DIRECTORY = process.env.SSL_CERT_DIRECTORY || path.join(__dirname, './ssl/cert');

module.exports = {
	SSL_CERT_DIRECTORY,
	port: 1812,
	// radius secret
	secret: 'testing123',

	authentication: 'StaticAuth',
	authenticationOptions: {
		validCredentials: [
			{ username: 'test', password: 'pwd' },
			{ username: 'user1', password: 'password' },
			{ username: 'admin', password: 'cool' }
		],
	},

	// certificate: {
	// 	cert: fs.readFileSync(path.join(SSL_CERT_DIRECTORY, '/server.crt')),
	// 	key: [
	// 		{
	// 			pem: fs.readFileSync(path.join(SSL_CERT_DIRECTORY, '/server.key')),
	// 			passphrase: 'whatever2020',
	// 		},
	// 	],
	// 	// sessionTimeout: 3600,
	// 	// sesionIdContext: 'meiasdfkljasdft!',
	// 	// ticketKeys: Buffer.from('123456789012345678901234567890123456789012345678'),
	// },

	// GoogleLDAPAuth (optimized for google auth)
	// authentication: 'GoogleLDAPAuth',
	// authenticationOptions: {
	// 	base: 'dc=hokify,dc=com',
	// 	// get your keys from http://admin.google.com/ -> Apps -> LDAP -> Client
	// 	tls: {
	// 		keyFile: 'ldap.gsuite.key',
	// 		certFile: 'ldap.gsuite.crt',
	// 	},
	// },

	/** LDAP AUTH 
	authentication: 'LDAPAuth',
	authenticationOptions: {
		url: 'ldaps://ldap.google.com',
		base: 'dc=hokify,dc=com',
		tls: {
			keyFile: 'ldap.gsuite.key',
			certFile: 'ldap.gsuite.crt'
		},
		tlsOptions: {
			servername: 'ldap.google.com'
		}
	}
	*/

	/** IMAP AUTH 
	authentication: 'IMAPAuth',
	authenticationOptions: {
		host: 'imap.gmail.com',
		port: 993,
		useSecureTransport: true,
		validHosts: ['hokify.com']
	}
	 */

	/** SMTP AUTH 
	authentication: 'IMAPAuth',
	authenticationOptions: {
		host: 'smtp.gmail.com',
		port: 465,
		useSecureTransport: true,
		validHosts: ['gmail.com']
	}
	 */
};
