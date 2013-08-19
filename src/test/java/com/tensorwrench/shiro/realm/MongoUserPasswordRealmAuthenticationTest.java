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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.HostAuthenticationToken;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.mongodb.BasicDBObject;
import com.tensorwrench.shiro.realm.MongoUserPasswordRealm;
import com.tensorwrench.testng.mongo.MongoData;
import com.tensorwrench.testng.mongo.MongoTestNG;

import static org.testng.Assert.*;

public class MongoUserPasswordRealmAuthenticationTest extends MongoTestNG {
  MongoUserPasswordRealm realm;
	
	@BeforeMethod
	protected void setupRealm() throws Exception {
		realm=new MongoUserPasswordRealm(getMongoDB().getCollection("principals"));
	}
	
	@Test
	public void supportsPassword() {
		assertTrue(realm.supports(new UsernamePasswordToken()),"Realm should support usernames and passwords.");
	}
		
	@Test(expectedExceptions={AuthenticationException.class})
	public void noHostSupport() {
		realm.doGetAuthenticationInfo(new HostAuthenticationToken() {
			private static final long	serialVersionUID	= 1L;
			@Override public Object getPrincipal() {return null;}
			@Override	public Object getCredentials() {return null;}
			@Override	public String getHost() {	return null;}
		}); 
	}

	//====================================================
	// Authentication tests
	//====================================================

	@Test @MongoData("/principals.json")
	public void findsUser() {
		AuthenticationInfo info=realm.findPasswordForUsername("mongoUser");
		assertNotNull(info);
	}
	
//	@Test
//	public void generateUser() {
//		DBObject obj=realm.createUserCredentials("user", "password");
//		System.out.println("Credentials for user:password are " + obj);
//	}
	
	@Test @MongoData("/principals.json")
	public void credentialsRoundTrip() {
		BasicDBObject principal=new BasicDBObject();
		principal.put(MongoUserPasswordRealm.DEFAULT_AUTH_FIELD, realm.createUserCredentials("generatedUser", "password"));
		principal.put("_id","generated-user-id");
		getMongoDB().getCollection("principals").insert(principal);
		System.out.println("Principal is " + principal);
		
		// now make sure we can find it
		AuthenticationInfo info=realm.getAuthenticationInfo(new UsernamePasswordToken("generatedUser","password"));
		
		assertEquals(info.getPrincipals().getPrimaryPrincipal(),"generated-user-id");
	}
	
	@Test(expectedExceptions={UnknownAccountException.class}) @MongoData("/principals.json")
	public void rejectsNonExistantUser() {
		assertNull(realm.doGetAuthenticationInfo(new UsernamePasswordToken("baduser","badpassword")));
	}
	
	@Test(expectedExceptions={AuthenticationException.class})
	public void rejectsNullUser() {
		realm.doGetAuthenticationInfo(new UsernamePasswordToken(null,"badpassword"));
	}

	@Test(expectedExceptions={UnknownAccountException.class})
	public void rejectsUserWithoutAuthUser() {
		realm.doGetAuthenticationInfo(new UsernamePasswordToken("noAuthInfo","badpassword"));
	}
	
	@Test(expectedExceptions={UnknownAccountException.class})
	public void rejectsUserWithBadAuthUser() {
		realm.doGetAuthenticationInfo(new UsernamePasswordToken("badAuthInfo","badpassword"));
	}

}
