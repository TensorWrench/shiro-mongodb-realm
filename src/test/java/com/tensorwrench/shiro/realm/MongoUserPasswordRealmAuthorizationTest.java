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

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.tensorwrench.shiro.realm.MongoUserPasswordRealm;
import com.tensorwrench.testng.mongo.MongoData;
import com.tensorwrench.testng.mongo.MongoTestNG;

import static org.testng.Assert.*;

@Test
public class MongoUserPasswordRealmAuthorizationTest extends MongoTestNG {	
	
  MongoUserPasswordRealm realm;
	
	@BeforeMethod
	protected void setupRealm() throws Exception {
		realm=new MongoUserPasswordRealm(getMongoDB().getCollection("principals"));
	}

		
	@Test @MongoData("/principals.json")
	public void getsUserRoles() {
		SimplePrincipalCollection principals=new SimplePrincipalCollection();
		principals.add("sample-principal-user","fooRealm");
		AuthorizationInfo info=realm.doGetAuthorizationInfo(principals);
		assertEqualsNoOrder(info.getRoles().toArray(),new String[] {"role:user"});
	}
	
	@Test @MongoData("/principals.json")
	public void getsAdminRoles() {
		SimplePrincipalCollection principals=new SimplePrincipalCollection();
		principals.add("sample-principal-admin","fooRealm");
		AuthorizationInfo info=realm.doGetAuthorizationInfo(principals);
		assertEqualsNoOrder(info.getRoles().toArray(),new String[] {"role:user","role:admin"});
	}	
}
