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
package com.tensorwrench.utils;

import com.mongodb.DBObject;

public class MongoUtils {
	static public Object getPath(DBObject base, String... path) {
		DBObject current=base;
		// descend, but skip the very last element
		for(int i=0;i < path.length-1;++i) {
			current=(DBObject) current.get(path[i]);
		}
		return current.get(path[path.length-1]);
	}

	@SuppressWarnings("unchecked")
	public static <T> T getPath(Class<T> clazz, DBObject obj, String[] path) {
		Object o = getPath(obj,path);
		if(clazz.isInstance(o)) {
			return (T) o;
		}
		return null;
	}
}
