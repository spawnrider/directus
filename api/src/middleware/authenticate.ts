/* eslint-disable no-inner-declarations */
/* eslint-disable prettier/prettier */
import { RequestHandler } from 'express';
import jwt, { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';
import getDatabase from '../database';
import env from '../env';
import { InvalidCredentialsException } from '../exceptions';
import asyncHandler from '../utils/async-handler';
import isJWT from '../utils/is-jwt';
import jwksClient from 'jwks-rsa'
import logger from '../logger';
import { UsersService } from '../services';
import { getSchema } from '../utils/get-schema';

/**
 * Verify the passed JWT and assign the user ID and role to `req`
 */
const authenticate: RequestHandler = asyncHandler(async (req, res, next) => {
	req.accountability = {
		user: null,
		role: null,
		admin: false,
		app: false,
		ip: req.ip.startsWith('::ffff:') ? req.ip.substring(7) : req.ip,
		userAgent: req.get('user-agent'),
	};

	if (!req.token) return next();

	const database = getDatabase();

	if (isJWT(req.token)) {

		/**
		 * NOTE: Security Patch for creating / authorizing on-the-fly authenticated users from Microsoft Azure AD.
		 * This patch is used to check JWT token against a specific SSO OAuth2 IdP (in our case, Microsoft Azure AD).
		 * If the JWT user (identified by its email address) does not exist in Directus, we will create it with a default role.
		 * Only users from a specific email domain will be created on the system (in our case, xxx.com)
		 * Then, we will authorize this user.   
		 * 
		 * Env. variables : 
		 * - env.OAUTH_AUTH_ISSUER : https://sts.windows.net/{tenandId}}/
		 * - env.OAUTH_USER_CREATION_DOMAIN_WHITELIST : xxx.com, xyz.fr
		 * - env.OAUTH_USER_CREATION_DEFAULT_ROLE : employee
		 * - env.OAUTH_AUTH_JWKS_URI : https://login.microsoftonline.com/{tenandId}/discovery/keys
		 */

		const decodedToken : any = jwt.decode(req.token);

		const issuer = env.OAUTH_AUTH_ISSUER;
		if(issuer && decodedToken && decodedToken.iss === issuer) {
			try {
				// Retrieve signing keys from a JWKS online endpoint
				const client = jwksClient({
					jwksUri: env.OAUTH_AUTH_JWKS_URI,
					cache: true
				});
				
				// Retrieve the key asssociate to the JWT header kid
				function getKey(header : any, callback: any) {
					client.getSigningKey(header.kid, function (err : any, key : any) {
						const signingKey = key.publicKey || key.rsaPublicKey;
						callback(err, signingKey);
					});
				};
		
				// Verify the token (signature and issuer) and extract info from it
				const options =  {issuer: issuer };

				const verifyToken = function(token: string) {
					return new Promise(function(resolve, reject) {
						jwt.verify(token, getKey, options, function(err : any, decoded : any) {
							if(err) {
								reject(err)
							} else {
								resolve(decoded) 
							}
						});
					});
				};
					
				const verifiedToken : any = await verifyToken(req.token);
				  
				// Check if the user is in the domain whitelist
				const email = verifiedToken.email;
				const whitelistedDomains = env.OAUTH_USER_CREATION_DOMAIN_WHITELIST?.split(",").map((d : any) => d.trim());
				const emailDomainIsWhitelisted = whitelistedDomains?.some((d : any) => email.endsWith(d)) ?? false;
	
				if(!emailDomainIsWhitelisted) {
					throw new InvalidCredentialsException('Domain not whitelisted.');
				}

				// Check if the user already exists
				const existingUser = await database("directus_users")
					.where({ email })
					.first();
				
				
				// Create the user if not exist
				if (!existingUser) {
					const schema = await getSchema();
					const usersService = new UsersService({
						schema,
						knex: database
					});

					const defaultRole = env.OAUTH_USER_CREATION_DEFAULT_ROLE;

					const user : any = await usersService.createOne({
                        first_name: verifiedToken.given_name,
                        last_name: verifiedToken.family_name,
                        email: email,
                        status: 'active',
                        role: defaultRole
					});

					logger.info(`New user was created : ${email}`);
				}

				// Retrieve the user with his role from the databse
				const user = await database
					.select('role', 'directus_roles.admin_access', 'directus_roles.app_access')
					.from('directus_users')
					.leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
					.where({
						'directus_users.email': email,
						status: 'active',
					})
					.first();

				logger.info(`User authenticated : ${email}`);

				req.accountability.user = user.id;
				req.accountability.role = user.role;
				req.accountability.admin = user.admin_access === true || user.admin_access == 1;
				req.accountability.app = user.app_access === true || user.app_access == 1;
				
			} catch (err) {
				logger.warn(err, `Issue with custom OAuth2 token. ${err.message}`);
				throw new InvalidCredentialsException('OAuth Token invalid.');
			}
		} else {
			// internal token validation
			let payload: { id: string };

			try {
				payload = jwt.verify(req.token, env.SECRET as string) as { id: string };
			} catch (err) {
				if (err instanceof TokenExpiredError) {
					throw new InvalidCredentialsException('Token expired.');
				} else if (err instanceof JsonWebTokenError) {
					throw new InvalidCredentialsException('Token invalid.');
				} else {
					throw err;
				}
			}

			const user = await database
				.select('role', 'directus_roles.admin_access', 'directus_roles.app_access')
				.from('directus_users')
				.leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
				.where({
					'directus_users.id': payload.id,
					status: 'active',
				})
				.first();

			if (!user) {
				throw new InvalidCredentialsException();
			}
	
			req.accountability.user = payload.id;
			req.accountability.role = user.role;
			req.accountability.admin = user.admin_access === true || user.admin_access == 1;
			req.accountability.app = user.app_access === true || user.app_access == 1;
		}
	} else {
		// Try finding the user with the provided token
		const user = await database
			.select('directus_users.id', 'directus_users.role', 'directus_roles.admin_access', 'directus_roles.app_access')
			.from('directus_users')
			.leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
			.where({
				'directus_users.token': req.token,
				status: 'active',
			})
			.first();

		if (!user) {
			throw new InvalidCredentialsException();
		}

		req.accountability.user = user.id;
		req.accountability.role = user.role;
		req.accountability.admin = user.admin_access === true || user.admin_access == 1;
		req.accountability.app = user.app_access === true || user.app_access == 1;
	}

	return next();
});

export default authenticate;
