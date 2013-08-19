/*
Copyright 2013 TensorWrench, LLC 

Licensed under the Apache License, Version 2.0 (the "License"); 
you may not use this file except in compliance with the License. 
You may obtain a copy of the License at 

http://www.apache.org/licenses/LICENSE-2.0 

Unless required by applicable law or agreed to in writing, software 
distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions and 
limitations under the License.
*/
package com.tensorwrench.shiro.realm;


import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import com.mongodb.BasicDBObject;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.tensorwrench.utils.MongoUtils;

/**
 *  Does authentication and authorization from a MongoDB.
 *  Expects the documents to have a several fields:
 *  <ul>
 *  <li> passwordAuthentication - object with authentication info
 *  <ul>
 *     <li>name - user name
 *     <li>password - password hash
 *     <li>salt - salt value used when the password was hashed
 *     <li>algorithm - Currently only supports Sha256Hash
		   <li>hashIterations - number of iterations used in the hash.  not used when validating the password, so don't change it (fix later)
 *  </ul>
 *  <li>roles - an array of roles
 *  <li>permissions - an array of permissions
 *  <ul>
 */
public class MongoUserPasswordRealm extends AuthorizingRealm {
	public static final String DEFAULT_AUTH_FIELD="passwordAuthentication";
	public static final String DEFAULT_NAME_FIELD=DEFAULT_AUTH_FIELD+".name";
	public static final String[] DEFAULT_PASSWORD_FIELD=new String[] {DEFAULT_AUTH_FIELD,"password"};
	public static final String[] DEFAULT_SALT_FIELD=new String[] {DEFAULT_AUTH_FIELD,"salt"};
	
	protected int hashIterations=100000;
	protected String userNamePath=DEFAULT_NAME_FIELD; 
	protected String[] passwordPath=DEFAULT_PASSWORD_FIELD;
	protected String[] saltPath=DEFAULT_SALT_FIELD;
	
	protected DBCollection collection;
	
	protected HashedCredentialsMatcher matcher=new HashedCredentialsMatcher(Sha256Hash.ALGORITHM_NAME);
	RandomNumberGenerator rng = new SecureRandomNumberGenerator();
	
	public MongoUserPasswordRealm() {
		matcher.setHashIterations(hashIterations);
		matcher.setStoredCredentialsHexEncoded(false);
		setCredentialsMatcher(matcher);
	}
	
	public MongoUserPasswordRealm(DBCollection collection) {
		this();
		this.collection=collection;
	}
	
	
	public void setCollection(DBCollection collection) {
		this.collection = collection;
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		return token instanceof UsernamePasswordToken;
	}
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authToken) throws AuthenticationException {
		if(!(authToken instanceof UsernamePasswordToken)) {
			throw new AuthenticationException("This realm only supports UsernamePasswordTokens");
		}
		UsernamePasswordToken token=(UsernamePasswordToken) authToken;

		if(token.getUsername() == null) {
			throw new AuthenticationException("Cannot log in null user");
		}
		
		return findPasswordForUsername(token.getUsername());
	}
	
	/**
	 * Does the actual mechanics of creating the Authentication info object from the database.
	 */
	public AuthenticationInfo findPasswordForUsername(String username) {
		DBObject obj=collection.findOne(
				new BasicDBObject(userNamePath,username)
		);
		
		if(obj == null) {
			throw new UnknownAccountException("Unkown user " + username);
		}
		
		String password=MongoUtils.getPath(String.class,obj ,passwordPath);
		String salt=MongoUtils.getPath(String.class, obj, saltPath);
		return new SimpleAuthenticationInfo(obj.get("_id"),password,Sha256Hash.fromBase64String(salt),getName());
	}

	/**
	 * Creates a user credential suitable for use with this realm.  Intended for
	 * creating the credentials to be inserted into the collection for later use.
	 * 
	 */
	public DBObject createUserCredentials(String username,String plainTextPassword) {
		ByteSource salt = rng.nextBytes();

		BasicDBObject obj=new BasicDBObject();
		obj.put("name", username);
		obj.put("password", new Sha256Hash(plainTextPassword, salt, hashIterations).toBase64());
		obj.put("salt", salt.toBase64());
		obj.put("algorithm", Sha256Hash.ALGORITHM_NAME);
		obj.put("hashIterations", hashIterations);
		return obj;
	}
	
	
	@SuppressWarnings("unchecked")
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		SimpleAuthorizationInfo info=new SimpleAuthorizationInfo();
		
		DBCursor cursor=collection.find(
				new BasicDBObject("_id",
						new BasicDBObject("$in",principals.asList())
				)
		);

		for(DBObject p : cursor){
			Object rolesObj=p.get("roles");
			if(rolesObj !=null && rolesObj instanceof List<?>) {
				for(Object r: (List<Object>) rolesObj) {
					info.addRole(r.toString());
				}
			}

			Object permissionsObj=p.get("permissions");
			if(permissionsObj !=null && permissionsObj instanceof List<?>) {
				for(Object r: (List<Object>) permissionsObj) {
					info.addStringPermission(r.toString());
				}
			}
		}
		
		return info;
	}
}
